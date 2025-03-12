#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <linux/random.h>
#include "cryptomod.h"

struct cryptodev_state {
    bool is_finalized;
    bool is_setup;

    enum CryptoMode crypto_mode;
    enum IOMode io_mode;
    int key_length;
    char key[CM_KEY_MAX_LEN];

    u8 buf[CM_BUF_SIZE];
    size_t buf_len;

    size_t remaining;
};

static dev_t devnum;
static struct cdev c_dev;
static struct class *clazz;

static unsigned long total_bytes_read = 0;
static unsigned long total_bytes_written = 0;
static int bytes_freq[16][16];
static DEFINE_MUTEX(lock);

void update_bytes_freq(u8 *buf, size_t len) {
    for(int i = 0; i < len; i++) {
        mutex_lock(&lock);
        bytes_freq[buf[i] >> 4][buf[i] & 0x0F]++;
        mutex_unlock(&lock);
    }
}

static int apply_pkcs7_padding(u8 *data, size_t datasize) {
    int padding = CM_BLOCK_SIZE - (datasize % CM_BLOCK_SIZE);

    for(int i = 0; i < padding; i++) data[datasize + i] = padding;
    
    return padding;
}

static int remove_pkcs7_padding(u8 *data, size_t datasize) {
    int padding = data[datasize - 1];

    if(padding > CM_BLOCK_SIZE) return -1;

    for(int i = 0; i < padding; i++)
        if(data[datasize - 1 - i] != padding) return -1;

    return padding;
}

static int encryption_decryption(u8 *data, size_t datasize, char* key, size_t key_len, int mode) {
    struct crypto_skcipher *tfm = NULL;
    struct skcipher_request *req = NULL;
    struct scatterlist sg;
    DECLARE_CRYPTO_WAIT(wait);
    int err;

    tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("Error allocating ecb(aes) handle: %ld\n", PTR_ERR(tfm));
        return PTR_ERR(tfm);
    }

    err = crypto_skcipher_setkey(tfm, key, key_len);
    if (err) {
        pr_err("Error setting key: %d\n", err);
        goto out;
    }

    /* Allocate a request object */
    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
        err = -ENOMEM;
        goto out;
    }

    sg_init_one(&sg, data, datasize); // You need to make sure that data size is mutiple of block size
    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP, crypto_req_done, &wait);
    skcipher_request_set_crypt(req, &sg, &sg, datasize, NULL);
    
    if(mode == ENC) err = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
    else if(mode == DEC) err = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
    
    if (err) {
        pr_err("Error encrypting data: %d\n", err);
        goto out;
    }

out:
    crypto_free_skcipher(tfm);
    skcipher_request_free(req);
    return err;
}  

static int cryptomod_dev_open(struct inode *i, struct file *f) {
    struct cryptodev_state *state = kmalloc(sizeof(struct cryptodev_state), GFP_KERNEL);
    if (state == NULL) return -ENOMEM;

    state->is_finalized = false;
    state->is_setup = false;
    state->key_length = 0;

    f->private_data = state;
    printk(KERN_INFO "cryptomod: device opened.\n");

    return 0;
}

static int cryptomod_dev_close(struct inode *i, struct file *f) {
    struct cryptodev_state *state = f->private_data;
    if(state != NULL) kfree(state);

    printk(KERN_INFO "cryptomod: device closed.\n");
    return 0;
}

static ssize_t cryptomod_dev_write(struct file *f, const char __user *user_buf, size_t len, loff_t *off) {
    struct cryptodev_state *state = f->private_data;

    /*** Check if device is properly set up or already finalized ***/
    if(!state->is_setup || state->is_finalized) {
        pr_err("cryptomod: Device not set up or already finalized.\n");
        return -EINVAL;
    }

    if(len == 0) return 0;

    if(state->io_mode == BASIC) {
        int err = copy_from_user(state->buf + state->buf_len, user_buf, len);
        /*** Copying data from user space to kernel space has failed ***/
        if(err) {
            pr_err("cryptomod: Failed to copy data from user space.\n");
            return -EBUSY;
        }
        state->buf_len += len;
        
        total_bytes_written += len;

        return len;
    }
    else if(state->io_mode == ADV) {
        if(state->crypto_mode == ENC) {
            size_t blocks = len / CM_BLOCK_SIZE;
            state->remaining = len % CM_BLOCK_SIZE;

            for(size_t i = 0; i < blocks; i++) {
                int err = copy_from_user(state->buf + state->buf_len, user_buf + i * CM_BLOCK_SIZE, CM_BLOCK_SIZE);
                if(err) {
                    pr_err("cryptomod: Failed to copy data from user space.\n");
                    return -EBUSY;
                }
                
                state->buf_len += CM_BLOCK_SIZE;
                encryption_decryption(state->buf + state->buf_len - CM_BLOCK_SIZE, CM_BLOCK_SIZE, state->key, state->key_length, state->crypto_mode);

            }

            mutex_lock(&lock);
            total_bytes_written += blocks * CM_BLOCK_SIZE;
            mutex_unlock(&lock);

            return blocks * CM_BLOCK_SIZE;
        }
        else if(state->crypto_mode == DEC) {
            int err = copy_from_user(state->buf + state->buf_len, user_buf, len);
            if(err) {
                pr_err("cryptomod: Failed to copy data from user space.\n");
                return -EBUSY;
            }

            state->buf_len += len;

            mutex_lock(&lock);
            total_bytes_written += len;
            mutex_unlock(&lock);

            return len;
        }
        
    }   

    return 0;
}

static ssize_t cryptomod_dev_read(struct file *f, char __user *user_buf, size_t len, loff_t *off) {
    struct cryptodev_state *state = f->private_data;

    /*** Check if the device is not properly setup ***/
    if(!state->is_setup) {
        pr_err("cryptomod: Device not set up or already finalized.\n");
        return -EINVAL;
    }

    /*** If not data is available and CM_IOC_FINALIZE has been called ***/
    if(state->is_finalized && state->buf_len == 0) {
        pr_info("cryptomod: CM_IOC_FINALIZE has been called, no data to read.\n");
        return 0;
    }


    if(state->io_mode == BASIC) {
        if(*off >= state->buf_len) return 0;

        size_t available = state->buf_len - *off;
        size_t to_copy = len > available ? available : len;

        int err = copy_to_user(user_buf, state->buf + *off, to_copy);
        if(err) {
            pr_err("Failed to copy data to user space.\n");
            return -EBUSY;
        }

        if(state->crypto_mode == ENC) update_bytes_freq(user_buf, to_copy);

        *off += to_copy;
        total_bytes_read += to_copy;

        return to_copy;
    }
    else if(state->io_mode == ADV) {
        
        if(state->crypto_mode == ENC) {
            if(*off >= state->buf_len) {
                memset(state->buf, 0, CM_BUF_SIZE);
                state->buf_len = 0;
                *off = 0;
                return 0;
            }
    
            size_t available = state->buf_len - *off;
            size_t to_copy = len > available ? available : len;
    
            int err = copy_to_user(user_buf, state->buf + *off, to_copy);
            if(err) {
                pr_err("Failed to copy data to user space.\n");
                return -EBUSY;
            }
    
            update_bytes_freq(user_buf, to_copy);
            
            *off += to_copy;
            total_bytes_read += to_copy;
    
            return to_copy;
        }
        else if(state->crypto_mode == DEC) {
            if (*off >= state->buf_len) return 0;

            size_t available = state->buf_len - *off;

            if (available <= CM_BLOCK_SIZE && !state->is_finalized) return 0;

            size_t to_copy = len > available ? available : len;

            if (available <= CM_BLOCK_SIZE && state->is_finalized) {
                u8 temp[CM_BLOCK_SIZE];
                memcpy(temp, state->buf + *off, CM_BLOCK_SIZE);
        
                encryption_decryption(temp, CM_BLOCK_SIZE, state->key, state->key_length, state->crypto_mode);
                int padding = remove_pkcs7_padding(temp, CM_BLOCK_SIZE);
                if (padding < 0) {
                    pr_warn("cryptomod: Invalid padding.\n");
                    return -EINVAL;
                }
        
                size_t actual_data_size = CM_BLOCK_SIZE - padding;
                if (copy_to_user(user_buf, temp, actual_data_size)) {
                    pr_err("cryptomod: Failed to copy decrypted data to user space.\n");
                    return -EBUSY;
                }
        
                state->buf_len -= padding;
                *off += actual_data_size;
                total_bytes_read += actual_data_size;
        
                return actual_data_size;
            }

            size_t blocks = to_copy / CM_BLOCK_SIZE;

            for (size_t i = 0; i < blocks; i++) {
                u8 temp[CM_BLOCK_SIZE];
                memcpy(temp, state->buf + *off + i * CM_BLOCK_SIZE, CM_BLOCK_SIZE);
                encryption_decryption(temp, CM_BLOCK_SIZE, state->key, state->key_length, state->crypto_mode);
                if (copy_to_user(user_buf + i * CM_BLOCK_SIZE, temp, CM_BLOCK_SIZE)) {
                    pr_err("cryptomod: Failed to copy decrypted data to user space.\n");
                    return -EBUSY;
                }
            }

            *off += blocks * CM_BLOCK_SIZE;
            total_bytes_read += blocks * CM_BLOCK_SIZE;

            return blocks * CM_BLOCK_SIZE;
        }
    }

    return 0;
    
}

static long cryptomod_dev_ioctl(struct file *fp, unsigned int cmd, unsigned long arg) {
    struct cryptodev_state *state = fp->private_data;
    struct CryptoSetup setup;

    if(state == NULL) return -EINVAL;

    switch (cmd) {
        case CM_IOC_SETUP:
            if(copy_from_user(&setup, (struct CryptoSetup __user *)arg, sizeof(struct CryptoSetup)) != 0) {
                return -EINVAL;
            }
            
            if(setup.key_len != 16 && setup.key_len != 24 && setup.key_len != 32) {
                printk(KERN_WARNING "cryptomod: Invalid key length. Expected 16, 24, or 32.\n");
                return -EINVAL;
            }

            if(setup.io_mode != BASIC && setup.io_mode != ADV) {
                printk(KERN_WARNING "cryptomod: Invalid IO Mode.\n");
                return -EINVAL;
            }

            if(setup.c_mode != ENC && setup.c_mode != DEC) {
                printk(KERN_WARNING "cryptomod: Invalid Crypto Mode.\n");
                return -EINVAL;
            }
            
            state->is_finalized = false;
            state->is_setup = true;
            
            state->crypto_mode = setup.c_mode;
            state->io_mode = setup.io_mode;

            state->key_length = setup.key_len;
            memcpy(state->key, setup.key, setup.key_len);

            memset(state->buf, 0, CM_BUF_SIZE);
            state->buf_len = 0;

            printk(KERN_INFO "CRYPTOMOD: SETUP COMPLETED, IO_MOD: %d, CRYPTO_MOD: %d\n", state->io_mode, state->crypto_mode);
            break;
        
        case CM_IOC_FINALIZE:
            if(!state->is_setup) {
                printk(KERN_WARNING "cryptomod: Finalized before setup");
                return -EINVAL;
            }

            if(state->is_finalized) {
                printk(KERN_WARNING "cryptomod: Already finalized.\n");
                return -EINVAL;
            }

            printk(KERN_INFO "CRYPTOMOD: DEVICE HAS BEEN FINALIZED.\n\n");
            
            if(state->io_mode == BASIC) {
                if(state->crypto_mode == ENC) {
                    int padding = apply_pkcs7_padding(state->buf, state->buf_len);
                    if(padding < 0) {
                        printk(KERN_WARNING "cryptomod: Invalid padding.\n");
                        return -EINVAL;
                    }
                    state->buf_len += padding;
    
                    encryption_decryption(state->buf, state->buf_len, state->key, state->key_length, state->crypto_mode);
                } 
                else if(state->crypto_mode == DEC) {
                    encryption_decryption(state->buf, state->buf_len, state->key, state->key_length, state->crypto_mode);
                    
                    int padding = remove_pkcs7_padding(state->buf, state->buf_len);
                    if(padding < 0) {
                        printk(KERN_WARNING "cryptomod: Invalid padding.\n");
                        return -EINVAL;
                    }
    
                    state->buf_len -= padding;
                }
            }
            else if(state->io_mode == ADV) {
                if(state->crypto_mode == ENC) {
                    u8 temp[CM_BLOCK_SIZE];
                    memcpy(temp, state->buf + state->buf_len, state->remaining);
                    int padding = apply_pkcs7_padding(temp, state->remaining);
                    if(padding < 0) {
                        printk(KERN_WARNING "cryptomod: Invalid padding.\n");
                        return -EINVAL;
                    }

                    encryption_decryption(temp, CM_BLOCK_SIZE, state->key, state->key_length, state->crypto_mode);

                    memcpy(state->buf + state->buf_len, temp, CM_BLOCK_SIZE);
                    state->buf_len += CM_BLOCK_SIZE;
                } 
            }

            state->is_finalized = true;
            break;
        
        case CM_IOC_CLEANUP:
            if(!state->key_length) {
                printk(KERN_WARNING "cryptomod: Device not set up.\n");
                return -EINVAL;
            }

            state->is_finalized = false;

            state->key_length = 0;
            memset(state->key, 0, CM_KEY_MAX_LEN);

            kfree(state->buf);
            state->buf_len = 0;

            printk(KERN_INFO "CRYPTOMOD: Device HAS BEEN CLEANED UP.\n");
            break;
        
        case CM_IOC_CNT_RST:
            total_bytes_read = 0;
            total_bytes_written = 0;
            memset(bytes_freq, 0, sizeof(bytes_freq));

            printk(KERN_INFO "CRYPTOMOD: DEVICE COUNTER HAS BEEN RESET.\n");
            break;
        }   

    return 0;
}

static const struct file_operations cryptomod_dev_fops = {
    .owner = THIS_MODULE,
    .open = cryptomod_dev_open,
    .read = cryptomod_dev_read,
    .write = cryptomod_dev_write,
    .unlocked_ioctl = cryptomod_dev_ioctl,
    .release = cryptomod_dev_close
};

static int cryptomod_proc_read(struct seq_file *m, void *v) {
    unsigned int i, j;
    seq_printf(m, "%lu %lu\n", total_bytes_read, total_bytes_written);
    for(i = 0; i < 16; i++) {
        for(j = 0; j < 16; j++) {
            seq_printf(m, "%3d ", bytes_freq[i][j]);
        }
        seq_printf(m, "\n");
    }

    return 0;
}

static int cryptomod_proc_open(struct inode *inode, struct file *file) {
    return single_open(file, cryptomod_proc_read, NULL);
}

static const struct proc_ops cryptomod_proc_fops = {
    .proc_open = cryptomod_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static char *cryptomod_devnode(const struct device *dev, umode_t *mode) {
    if (mode == NULL) return NULL;
    *mode = 0666;
    return NULL;
}

static int __init cryptomod_init(void) {
    if (alloc_chrdev_region(&devnum, 0, 1, "cryptodev") < 0) return -1;
    if ((clazz = class_create("cryptoclass")) == NULL) goto release_region;
    clazz->devnode = cryptomod_devnode;
    
    if (device_create(clazz, NULL, devnum, NULL, "cryptodev") == NULL) goto release_class;
    cdev_init(&c_dev, &cryptomod_dev_fops);
    if (cdev_add(&c_dev, devnum, 1) == -1) goto release_device;

    proc_create("cryptomod", 0666, NULL, &cryptomod_proc_fops);

    printk(KERN_INFO "cryptomod: initialized.\n");
    return 0;

release_device:
    device_destroy(clazz, devnum);
release_class:
    class_destroy(clazz);
release_region:
    unregister_chrdev_region(devnum, 1);
    return -1;
}

static void __exit cryptomod_cleanup(void) {
    remove_proc_entry("cryptomod", NULL);

    cdev_del(&c_dev);
    device_destroy(clazz, devnum);
    class_destroy(clazz);
    unregister_chrdev_region(devnum, 1);

    printk(KERN_INFO "cryptomod: cleaned up.\n");
}

module_init(cryptomod_init);
module_exit(cryptomod_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tony");
MODULE_DESCRIPTION("Crypto module for the UNIX programming course.");