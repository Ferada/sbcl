;;; -*- Mode: Lisp; Package: X86 -*-
;;;
;;; **********************************************************************
;;; This code was written by Douglas T. Crosher and has been placed in
;;; the Public domain, and is provided 'as is'.
;;;
#+(or)
(ext:file-comment
  "$Header: /home/dtc/cvs/src/cmucl/p86/compiler/x86/syscall-linux.lisp,v 1.12 1999/09/13 16:39:03 dtc Exp $")
;;;
;;; **********************************************************************
;;;
;;; Support for direct system calls. These have the advantage that the
;;; errno is handled safely.
;;;
;;; Contributions from Peter Van Eynde 1999.

(in-package "SB!VM")



;;; Linux systems call arguments are passed in registers.
;;;
;;; String arguments are kept live until after the sycall to prevent
;;; the object being moved in case of a garbage collection.
;;;
(defmacro define-syscall-vop (&rest arguments)
  "Defines a Linux syscall vop for given arguments. The arguments are
  either :signed, :unsigned, :string, or :sap."
  (collect ((vop-suffixes) (args) (arg-types) (temps) (loads))
    (do ((arguments arguments (rest arguments))
         (arg-num 0 (1+ arg-num))
         (arg-regs '(rdi rsi rdx r10 r8 r9) (rest arg-regs)))
        ((endp arguments))
      (let* ((argument (first arguments))
             (name (symbolicate "ARG" (format nil "~D" arg-num)))
             (arg-reg (first arg-regs))
             (scs (ecase argument
                    (:signed 'signed-reg)
                    (:unsigned 'unsigned-reg)
                    (:string 'descriptor-reg)
                    (:sap 'sap-reg))))
        (vop-suffixes (ecase argument
                        (:signed '-signed)
                        (:unsigned '-unsigned)
                        (:string '-string)
                        (:sap '-sap)))
        (args (if (eq argument :string)
                  `(,name :scs (,scs) :to :result)
                  `(,name :scs (,scs) :target ,arg-reg)))
        (arg-types (ecase argument
                     (:signed 'signed-num)
                     (:unsigned 'unsigned-num)
                     (:string 'simple-character-string)
                     (:sap 'system-area-pointer)))
        (temps `(:temporary (:sc ,(ecase argument
                                    (:signed 'signed-reg)
                                    (:unsigned 'unsigned-reg)
                                    (:string 'unsigned-reg)
                                    (:sap 'sap-reg))
                             :offset ,(symbolicate arg-reg "-OFFSET")
                             :from (:argument ,arg-num)
                             :to :eval)
                            ,arg-reg))
        (loads (if (eq argument :string)
                   `(inst lea ,arg-reg
                          (make-ea :byte :base ,name
                                   :disp (- (* vector-data-offset n-word-bytes)
                                            other-pointer-lowtag)))
                   `(move ,arg-reg ,name)))))
    `(define-vop (,(apply #'symbolicate "%UNIX-SYSCALL"
                          (or (vop-suffixes) '("-VOID"))))
       (:policy :fast-safe)
       (:args ,@(args))
       (:arg-types ,@(arg-types))
       ,@(temps)
       (:temporary (:sc signed-reg :offset rax-offset
                        :from :eval :to :result :target result) rax)
       (:results (result :scs (signed-reg))
                 (errno :scs (unsigned-reg)))
       (:result-types signed-num unsigned-num)
       (:variant-vars syscall-number)
       (:generator 1
          (let ((error (gen-label))
                (done (gen-label)))
            ,@(loads)
            (inst mov rax syscall-number)
            (inst syscall)
            (inst cmp rax -4095)
            (inst jmp :ae error)
            (move result rax)
            (inst xor errno errno)
            (emit-label done)

            (assemble (*elsewhere*)
              (emit-label error)
              (inst neg rax)
              (move errno rax)
              (inst mov result -1)
              (inst jmp done)))))))

(defmacro define-syscall (vop-name number result-type &rest arguments)
  "Define a syscall with the given number, result type, and
  arguments which may be :signed, :unsigned, :sap, or :string."
  (collect ((vop-suffixes) (arg-types))
    (do ((arguments arguments (rest arguments))
         (arg-num 0 (1+ arg-num)))
        ((endp arguments))
      (let ((argument (first arguments)))
        (vop-suffixes (ecase argument
                        (:signed '-signed)
                        (:unsigned '-unsigned)
                        (:string '-string)
                        (:sap '-sap)))
        (arg-types (ecase argument
                     (:signed '(signed-byte 32))
                     (:unsigned '(unsigned-byte 32))
                     (:string 'simple-string)
                     (:sap 'system-area-pointer)))))
    (let ((name (intern (symbol-name vop-name) "SB-UNIX")))
      `(progn
         (defknown ,name ,(arg-types) (values ,result-type (unsigned-byte 12)))
         (define-vop (,vop-name ,(apply #'symbolicate "%UNIX-SYSCALL"
                                        (or (vop-suffixes) '("-VOID"))))
           (:translate ,name)
           (:variant ,number))))))

;;; Linux socket systems call arguments are passed on the stack.
;;;
;;; String arguments are kept live until after the sycall to prevent
;;; the object being moved in case of a garbage collection.
;;;
#+(or)
(defmacro define-socketcall-vop (&rest arguments)
  "Defines a Linux socket call vop for given arguments. The arguments are
  either :signed, :unsigned, :string, or :sap."
  (let ((loads ()))
    (collect ((vop-suffixes) (args) (arg-types))
      (do ((arguments arguments (rest arguments))
           (arg-num 0 (1+ arg-num)))
          ((endp arguments))
        (let* ((argument (first arguments))
               (name (symbolicate "ARG" (format nil "~D" arg-num)))
               (scs (ecase argument
                      (:signed 'signed-reg)
                      (:unsigned 'unsigned-reg)
                      (:string 'descriptor-reg)
                      (:sap 'sap-reg))))
          (vop-suffixes (ecase argument
                          (:signed '-signed)
                          (:unsigned '-unsigned)
                          (:string '-string)
                          (:sap '-sap)))
          (args (if (eq argument :string)
                    `(,name :scs (,scs) :to :result)
                    `(,name :scs (,scs) :to :eval)))
          (arg-types (ecase argument
                       (:signed 'signed-num)
                       (:unsigned 'unsigned-num)
                       (:string 'simple-string)
                       (:sap 'system-area-pointer)))
          (when (eq argument :string)
            (push `(inst add (make-ea :dword :base esp-tn)
                         (- (* vector-data-offset n-word-bytes)
                            other-pointer-type))
                   loads))
          (push `(inst push ,name) loads)))
      `(define-vop (,(apply #'symbolicate "%UNIX-SOCKETCALL" (vop-suffixes)))
         (:policy :fast-safe)
         (:args ,@(args))
         (:arg-types ,@(arg-types))
         (:temporary (:sc unsigned-reg :offset ebx-offset
                          :from :eval :to :result) ebx)
         (:temporary (:sc unsigned-reg :offset ecx-offset
                          :from :eval :to :result) ecx)
         (:temporary (:sc signed-reg :offset eax-offset
                          :from :eval :to :result :target result) eax)
         (:results (result :scs (signed-reg))
                   (errno :scs (unsigned-reg)))
         (:result-types signed-num unsigned-num)
         (:variant-vars subcode)
         (:generator 1
            (let ((error (gen-label))
                  (done (gen-label)))
              ,@loads
              (inst mov ecx esp-tn)
              (inst mov ebx subcode)
              (inst mov eax 102)
              (inst int #x80)
              (inst add esp-tn ,(* (length arguments) n-word-bytes))
              (inst cmp eax -4095)
              (inst jmp :ae error)
              (move result eax)
              (inst xor errno errno)
              (emit-label done)

              (assemble (*elsewhere*)
                (emit-label error)
                (inst neg eax)
                (move errno eax)
                (inst mov result -1)
                (inst jmp done))))))))

#+(or)
(defmacro define-socketcall (vop-name number result-type &rest arguments)
  "Define a Linux socket call with the given number, result type, and
  arguments which may be :signed, :unsigned, :sap, or :string."
  (collect ((vop-suffixes) (arg-types))
    (do ((arguments arguments (rest arguments))
         (arg-num 0 (1+ arg-num)))
        ((endp arguments))
      (let ((argument (first arguments)))
        (vop-suffixes (ecase argument
                        (:signed '-signed)
                        (:unsigned '-unsigned)
                        (:string '-string)
                        (:sap '-sap)))
        (arg-types (ecase argument
                     (:signed '(signed-byte 32))
                     (:unsigned '(unsigned-byte 32))
                     (:string 'simple-string)
                     (:sap 'system-area-pointer)))))
    (let ((name (intern (symbol-name vop-name) "SB-UNIX")))
      `(progn
         (defknown ,name ,(arg-types) (values ,result-type (unsigned-byte 12)))
         (define-vop (,vop-name ,(apply #'symbolicate "%UNIX-SOCKETCALL"
                                        (vop-suffixes)))
           (:translate ,name)
           (:variant ,number))))))


;;; Syscalls.

(define-syscall-vop)
(define-syscall %unix-fork         57 (signed-byte 32))
(define-syscall %unix-getpid       39 (signed-byte 32))
(define-syscall %unix-getuid      102 (signed-byte 32))
(define-syscall %unix-sync        162 (member 0))
(define-syscall %unix-getgid      104 (signed-byte 32))
(define-syscall %unix-geteuid     107 (signed-byte 32))
(define-syscall %unix-getegid     108 (signed-byte 32))
(define-syscall %unix-getppid     110 (signed-byte 32))
(define-syscall %unix-getpgrp     111 (signed-byte 32))
(define-syscall %unix-setsid      112 (signed-byte 32))
(define-syscall %unix-sched-yield  24 (member -1 0))

(define-syscall-vop :signed)
(define-syscall %unix-exit         60 (member -1 0) :signed)
(define-syscall %unix-close         3 (member -1 0) :signed)
(define-syscall %unix-dup          32 fixnum :signed)
(define-syscall %unix-fsync        74 (member -1 0) :signed)

(define-syscall-vop :signed :signed)
;;; setpgid; implements setpgrp as setpgid(0, 0).
(define-syscall %unix-setpgid     109 (member -1 0) :signed :signed)
(define-syscall %unix-dup2         33 fixnum :signed :signed)
(define-syscall %unix-setreuid    113 (member -1 0) :signed :signed)
(define-syscall %unix-setregid    114 (member -1 0) :signed :signed)

(define-syscall-vop :signed :unsigned)
(define-syscall %unix-ftruncate    77 (member -1 0) :signed :unsigned)
(define-syscall %unix-fchmod       91 (member -1 0) :signed :unsigned)

(define-syscall-vop :signed :signed :signed)
(define-syscall %unix-fcntl        72 (signed-byte 32) :signed :signed :signed)
(define-syscall %unix-fchown       93 (member -1 0) :signed :signed :signed)

(define-syscall-vop :signed :unsigned :sap)
(define-syscall %unix-ioctl        16 (member -1 0) :signed :unsigned :sap)

(define-syscall-vop :signed :sap)
(define-syscall %unix-getrusage    98 (member -1 0) :signed :sap)
(define-syscall %unix-getitimer    36 (member -1 0) :signed :sap)
(define-syscall %unix-fstat         5 (member -1 0) :signed :sap)

(define-syscall-vop :signed :sap :sap)
(define-syscall %unix-setitimer    38 (member -1 0) :signed :sap :sap)

(define-syscall-vop :signed :sap :unsigned)
(define-syscall %unix-read          0 (signed-byte 32) :signed :sap :unsigned)
(define-syscall %unix-write         1 (signed-byte 32) :signed :sap :unsigned)

(define-syscall-vop :signed :sap :sap :sap :sap)
(define-syscall %unix-select       23 fixnum :signed :sap :sap :sap :sap)

(define-syscall-vop :sap)
(define-syscall %unix-pipe         22 (member -1 0) :sap)
;;; uname; implements gethostname.
(define-syscall %unix-uname        63 (member -1 0) :sap)

(define-syscall-vop :sap :sap)
(define-syscall %unix-gettimeofday 96 (member -1 0) :sap :sap)

(define-syscall-vop :string)
(define-syscall %unix-unlink       87 (member -1 0) :string)
(define-syscall %unix-chdir        80 (member -1 0) :string)
(define-syscall %unix-rmdir        84 (member -1 0) :string)

(define-syscall-vop :string :signed)
(define-syscall %unix-access       21 (member -1 0) :string :signed)

(define-syscall-vop :string :unsigned)
(define-syscall %unix-chmod 15 (member -1 0) :string :unsigned)
(define-syscall %unix-mkdir 39 (member -1 0) :string :unsigned)
(define-syscall %unix-truncate 92 (member -1 0) :string :unsigned)

(define-syscall-vop :string :signed :signed)
(define-syscall %unix-chown 182 (member -1 0) :string :signed :signed)

(define-syscall-vop :string :signed :unsigned)
(define-syscall %unix-open 5 fixnum :string :signed :unsigned)

(define-syscall-vop :string :string)
(define-syscall %unix-link 9 (member -1 0) :string :string)
(define-syscall %unix-rename 38 (member -1 0) :string :string)
(define-syscall %unix-symlink 83 (member -1 0) :string :string)

(define-syscall-vop :string :sap)
;;; utime; used to implement utimes.
(define-syscall %unix-utime 30 (member -1 0) :string :sap)
(define-syscall %unix-stat 106 (member -1 0) :string :sap)
(define-syscall %unix-lstat 107 (member -1 0) :string :sap)

(define-syscall-vop :string :sap :signed)
(define-syscall %unix-readlink 85 fixnum :string :sap :signed)

(define-syscall-vop :string :sap :sap)
(define-syscall %unix-execve 11 (member -1 0) :string :sap :sap)


;;; Socket calls.

#+(or)
(progn
(define-socketcall-vop :signed :signed :signed)
(define-socketcall %unix-socket 1 fixnum :signed :signed :signed)

(define-socketcall-vop :signed :sap :signed)
(define-socketcall %unix-bind 2 (member -1 0) :signed :sap :signed)
(define-socketcall %unix-connect 3 (member -1 0) :signed :sap :signed)

(define-socketcall-vop :signed :signed)
(define-socketcall %unix-listen 4 (member -1 0) :signed :signed)

(define-socketcall-vop :signed :sap :sap)
(define-socketcall %unix-accept 5 fixnum :signed :sap :sap)
(define-socketcall %unix-getsockname 6 (member -1 0) :signed :sap :sap)
(define-socketcall %unix-getpeername 7 (member -1 0) :signed :sap :sap)

(define-socketcall-vop :signed :string :signed :unsigned)
(define-socketcall %unix-send 9 (signed-byte 32)
                   :signed :string :signed :unsigned)
(define-socketcall %unix-recv 10 (signed-byte 32)
                   :signed :string :signed :unsigned)
)


;;; Lseek.

;;; This version of %unix-lseek handles 64-bit offsets by passing and
;;; returning the high and low 32-bit words of the offset.
;;;
#+(or)
(defknown unix::%unix-lseek ((signed-byte 32)
                             (signed-byte 32) (unsigned-byte 32)
                             (signed-byte 32))
  (values (signed-byte 32) (unsigned-byte 32) (unsigned-byte 32)))

#+(or)
(define-vop (%unix-lseek)
  (:translate unix::%unix-lseek)
  (:policy :fast-safe)
  (:args (fd :scs (signed-reg) :target ebx)
         (offset-high :scs (signed-reg) :target ecx)
         (offset-low :scs (unsigned-reg) :target edx)
         (whence :scs (signed-reg) :target edi))
  (:arg-types signed-num signed-num unsigned-num signed-num)
  (:temporary (:sc signed-reg :offset ebx-offset
                   :from (:argument 0) :to :eval) ebx)
  (:temporary (:sc signed-reg :offset ecx-offset
                   :from (:argument 1) :to :eval) ecx)
  (:temporary (:sc unsigned-reg :offset edx-offset
                   :from (:argument 2) :to :eval) edx)
  (:temporary (:sc unsigned-reg :offset esi-offset
                   :from :eval :to :result) esi)
  (:temporary (:sc signed-reg :offset edi-offset
                   :from (:argument 4) :to :eval) edi)
  (:temporary (:sc signed-reg :offset eax-offset
                   :from :eval :to :result :target errno) eax)
  (:results (res-offset-high :scs (signed-reg))
            (res-offset-low :scs (unsigned-reg))
            (errno :scs (unsigned-reg)))
  (:result-types signed-num unsigned-num unsigned-num)
  (:generator 1
    (let ((error (gen-label))
          (done (gen-label)))
      (move ebx fd)
      (move ecx offset-high)
      (move edx offset-low)
      (move edi whence)
      (inst sub esp-tn 8)       ; Room for the 64 bit result.
      (inst mov esi esp-tn)
      (inst mov eax 140)
      (inst int #x80)
      (inst cmp eax -125)
      (inst jmp :ae error)
      (inst pop res-offset-low)
      (inst pop res-offset-high)
      (inst xor errno errno)
      (emit-label done)

      (assemble (*elsewhere*)
         (emit-label error)
         (inst neg eax)
         (move errno eax)
         (inst mov res-offset-high -1)
         (inst mov res-offset-low -1)
         (inst jmp done)))))
