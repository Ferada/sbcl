;; /usr/include/asm/unistd_64.h

(defmacro syscall ((name &rest arg-types) success-form &rest args)
  (when (eql 3 (mismatch "[_]" name))
    (setf name
          (concatenate 'string #!+win32 "_" (subseq name 3))))
  `(locally
    (declare (optimize (sb!c::float-accuracy 0)))
    (let ((result (alien-funcall (extern-alien ,name (function int ,@arg-types))
                                ,@args)))
      (if (minusp result)
          (values nil (get-errno))
          ,success-form))))

;;; This is like SYSCALL, but if it fails, signal an error instead of
;;; returning error codes. Should only be used for syscalls that will
;;; never really get an error.
(defmacro syscall* ((name &rest arg-types) success-form &rest args)
  `(locally
    (declare (optimize (sb!c::float-accuracy 0)))
    (let ((result (alien-funcall (extern-alien ,name (function int ,@arg-types))
                                 ,@args)))
      (if (minusp result)
          (error "Syscall ~A failed: ~A" ,name (strerror))
          ,success-form))))

(defmacro int-syscall ((name &rest arg-types) &rest args)
  `(syscall (,name ,@arg-types) (values result 0) ,@args))

;;; UNIX-WRITE accepts a file descriptor, a buffer, an offset, and the
;;; length to write. It attempts to write len bytes to the device
;;; associated with fd from the buffer starting at offset. It returns
;;; the actual number of bytes written.
(defun unix-write (fd buf offset len)
  (declare (type unix-fd fd)
           (type (unsigned-byte 32) offset len))
  (flet ((%write (sap)
           (declare (system-area-pointer sap))
           (int-syscall (#!-win32 "write" #!+win32 "win32_unix_write"
                         int (* char) int)
                        fd
                        (with-alien ((ptr (* char) sap))
                          (addr (deref ptr offset)))
                        len)))
    (etypecase buf
      ((simple-array * (*))
       (with-pinned-objects (buf)
         (%write (vector-sap buf))))
      (system-area-pointer
       (%write buf)))))

(define-instruction int (segment number)
  (:declare (type (unsigned-byte 8) number))
  (:printer byte-imm ((op #b11001101)))
  (:emitter
   (etypecase number
     ((member 3)
      (emit-byte segment #b11001100))
     ((unsigned-byte 8)
      (emit-byte segment #b11001101)
      (emit-byte segment number)))))

(define-instruction cpuid (segment)
  (:printer two-bytes ((op '(#b00001111 #b10100010))))
  (:emitter
   (emit-byte segment #b00001111)
   (emit-byte segment #b10100010)))

(sb-disassem:define-instruction-format (two-bytes 16
                                        :default-printer '(:name))
  (op :fields (list (byte 8 0) (byte 8 8))))

(define-vop (%read-cycle-counter)
  (:policy :fast-safe)
  (:translate %read-cycle-counter)
  (:temporary (:sc unsigned-reg :offset eax-offset :target lo) eax)
  (:temporary (:sc unsigned-reg :offset edx-offset :target hi) edx)
  (:temporary (:sc unsigned-reg :offset ebx-offset) ebx)
  (:temporary (:sc unsigned-reg :offset ecx-offset) ecx)
  (:ignore ebx ecx)
  (:results (hi :scs (unsigned-reg))
            (lo :scs (unsigned-reg)))
  (:result-types unsigned-num unsigned-num)
  (:generator 5
     (zeroize eax)
     ;; Intel docs seem quite consistent on only using CPUID before RDTSC,
     ;; not both before and after. Go figure.
     (inst cpuid)
     (inst rdtsc)
     (move lo eax)
     (move hi edx)))

00000000000cc3b0 <syscall>:
   cc3b0:       48 89 f8                mov    %rdi,%rax
   cc3b3:       48 89 f7                mov    %rsi,%rdi
   cc3b6:       48 89 d6                mov    %rdx,%rsi
   cc3b9:       48 89 ca                mov    %rcx,%rdx
   cc3bc:       4d 89 c2                mov    %r8,%r10
   cc3bf:       4d 89 c8                mov    %r9,%r8
   cc3c2:       4c 8b 4c 24 08          mov    0x8(%rsp),%r9
   cc3c7:       0f 05                   syscall
   cc3c9:       48 3d 01 f0 ff ff       cmp    $0xfffffffffffff001,%rax
   cc3cf:       73 01                   jae    cc3d2 <syscall+0x22>
   cc3d1:       c3                      retq
   cc3d2:       48 8b 0d bf fb 28 00    mov    0x28fbbf(%rip),%rcx        # 35bf98 <_IO_file_jumps+0xa98>
   cc3d9:       31 d2                   xor    %edx,%edx
   cc3db:       48 29 c2                sub    %rax,%rdx
   cc3de:       64 89 11                mov    %edx,%fs:(%rcx)
   cc3e1:       48 83 c8 ff             or     $0xffffffffffffffff,%rax
   cc3e5:       eb ea                   jmp    cc3d1 <syscall+0x21>

(deftype exit-code ()
  `(signed-byte 32))
(defun os-exit (code &key abort)
  #!+sb-doc
  "Exit the process with CODE. If ABORT is true, exit is performed using _exit(2),
avoiding atexit(3) hooks, etc. Otherwise exit(2) is called."
  (unless (typep code 'exit-code)
    (setf code (if abort 1 0)))
  (if abort
      (void-syscall ("_exit" int) code)
      (void-syscall ("exit" int) code)))

;; sb-linux contrib to transparently override calls to libc
;; i.e. sb-sys:os-exit, unix-write, etc.

;; if this is done early enough, the whole thing could possibly be
;; compiled without a libc on suitable platforms, i.e. linux x86-64

(in-package #:sb-vm)

(define-instruction syscall (segment)
  (:printer two-bytes ((op '(#b00001111 #b00000101))))
  (:emitter
   (emit-byte segment #b00001111)
   (emit-byte segment #b00000101)))

(define-instruction sysret (segment)
  (:printer two-bytes ((op '(#b00001111 #b00000111))))
  (:emitter
   (emit-byte segment #b00001111)
   (emit-byte segment #b00000111)))

(defmacro define-syscall-vop (&rest arguments)
  )

(defmacro define-syscall (vop-name number result-type &rest arguments))

;; rdi rsi rdx r10 r8 r9

(defknown %syscall/0 ((unsigned-byte 64)) (values) ())

(define-vop (%syscall/1)
  (:policy :fast-safe)
  (:translate %syscall/1)
  (:temporary (:sc unsigned-reg :offset rax-offset) rax)
  (:temporary (:sc unsigned-reg :offset rdi-offset) rdi)
  (:temporary (:sc unsigned-reg :offset rcx-offset) rcx)
  (:temporary (:sc unsigned-reg :offset r11-offset) r11)
  (:ignore rcx r11)
  (:args (syscall :scs (unsigned-reg immediate) :target rax)
         (arg :scs (signed-reg unsigned-reg immediate) :target rdi))
  (:arg-types unsigned-num (:or unsigned-num signed-num))
  (:generator 3
     (sc-case syscall
       (immediate
        (inst mov rax (tn-value syscall)))
       (unsigned-reg
        (move rax syscall)))
     (sc-case arg
       (immediate
        (inst mov rdi (constantize (tn-value arg))))
       ((signed-reg unsigned-reg)
        (move rdi arg)))
     (inst syscall)))

(defknown %syscall/1 ((unsigned-byte 64) (or (signed-byte 64) (unsigned-byte 64))) (values) ())

(define-vop (%syscall/1)
  (:policy :fast-safe)
  (:translate %syscall/1)
  (:temporary (:sc unsigned-reg :offset rax-offset) rax)
  (:temporary (:sc unsigned-reg :offset rdi-offset) rdi)
  (:temporary (:sc unsigned-reg :offset rcx-offset) rcx)
  (:temporary (:sc unsigned-reg :offset r11-offset) r11)
  (:ignore rcx r11)
  (:args (syscall :scs (unsigned-reg immediate) :target rax)
         (arg :scs (signed-reg unsigned-reg immediate) :target rdi))
  (:arg-types unsigned-num (:or unsigned-num signed-num))
  (:generator 3
     (sc-case syscall
       (immediate
        (inst mov rax (tn-value syscall)))
       (unsigned-reg
        (move rax syscall)))
     (sc-case arg
       (immediate
        (inst mov rdi (constantize (tn-value arg))))
       ((signed-reg unsigned-reg)
        (move rdi arg)))
     (inst syscall)))

;; exit would have to be done as an assembly routine to specify return-style :none
;; src/assembly/assemfile.lisp

(defconstant +syscall-exit+ 60)
(defconstant +syscall-exit-group+ 231)

(defun os-exit (code &key abort)
  (declare (type (signed-byte 64) code))
  (%syscall/1 +syscall-exit-group+ code))

(defun unix-getpid ()
  (%syscall/0 +syscall-getpid+))