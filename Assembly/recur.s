; nc up.zoolab.org 2518

; recur: implement a recursive function

;    r(n) = 0, if n <= 0
;         = 1, if n == 1
;         = 2*r(n-1) + 3*r(n-2), otherwise
   
;    please call r(27) and store the result in RAX
; ======
; * BASEADDR rsi = 0x5ea000, DATAADDR = BASEADDR + 0x200000
; ======