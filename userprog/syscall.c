#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "lib/kernel/stdio.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void halt (void);
void exit (int status);
tid_t fork (const char *thread_name);
int exec (const char *cmd_line);
int wait (tid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
bool check_address(const char *addr);
/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
	
	lock_init(&filesys_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	switch(f->R.rax){
		case SYS_HALT:
			halt();
		case SYS_EXIT:
			exit(f->R.rdi);
		case SYS_FORK:
			f->R.rax = fork(f->R.rdi);
		case SYS_EXEC:
			f->R.rax = exec(f->R.rdi);
		case SYS_WAIT:
			f->R.rax = wait(f->R.rdi);
		case SYS_CREATE:
			f->R.rax = create(f->R.rdi, f->R.rsi);
		case SYS_REMOVE:
			f->R.rax = remove(f->R.rdi);
		case SYS_OPEN:
			f->R.rax = open(f->R.rdi);
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
		case SYS_READ:
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
		case SYS_WRITE:
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);
		case SYS_TELL:
			f->R.rax = tell(f->R.rdi);
		case SYS_CLOSE:
			close(f->R.rdi);
	}
}

void halt (void){
	power_off();
}

void exit (int status){
	def_thread *curr = thread_current();
	printf("%s: exit(%d)\n", curr->name, status);
	thread_exit();
}
int exec (const char *cmd_line){}
int wait (tid_t pid){}

bool create (const char *file, unsigned initial_size){
	if(check_address(file)){
		filesys_create(file, initial_size);		
		return true;
	}else{
		return false;
	}
}

bool remove (const char *file){
	if(check_address(file)){
		filesys_remove(file);
		return true;
	}else{
		return false;
	}
}

int open (const char *file){
	check_address(file);
	struct file *f = filesys_open(file);
	if(f==NULL){
		return -1;
	}
	// 파일 객체에 대한 fd 생성.
	int fd;
	def_thread *curr = thread_current();
	struct file **fdt = curr->fdt;

	fd = curr->next_fd;
	while(curr->fdt[fd]!=NULL){
		fd++;
	}

	curr->next_fd = fd;
	fdt[fd] = f;

	if(fd == -1){
		file_close(f);
	}else{
		return fd;
	}
}

int filesize (int fd){
	if(fd < 0 || fd > 63){
		return 0;
	}

	// 프로세스의 fdt를 검색해서 파일 객체를 찾음.
	def_thread *curr = thread_current();
	struct file **fdt = curr->fdt;
	struct file *file = fdt[fd];

	if(file == NULL){
		return -1;
	}else{
		file_length(file);
	}
}

int read (int fd, void *buffer, unsigned size){
	uint8_t key;
	def_thread *curr = thread_current();
	struct file **fdt = curr->fdt;
	struct file *file = fdt[fd];	

	// fd가 0일 때(파일 끝에서 시도하는 경우), input_getc()로 키보드로부터 바이트를 읽는다.
	if(fd == 0){
		key = input_getc();
		return key;
	}
	// 해당 파일을 읽을 수 있다면 file_read()로 바이트를 읽는다. 읽을 수 없다면 -1 반환
	else {
		if(!is_user_vaddr(&buffer) || buffer == NULL) {
			return -1;
		}
		else {
			return file_read(file, buffer, size);
		}
	}
}

int write (int fd, const void *buffer, unsigned size) {
	def_thread *curr = thread_current();
	struct file **fdt = curr->fdt;
	struct file *file = fdt[fd];
	off_t write_size;
	if(fd == 1) {
		putbuf(buffer, size);
		return size;
	}
	else {		
		if(!is_user_vaddr(&buffer) || buffer == NULL) {
			return -1;
		}
		else {
			write_size = file_write(file, buffer, size);
			return write_size;
		}
	}
}

// 파일을 특정위치로 이동시키는 함수.
void seek (int fd, unsigned position){
	if(fd < 3){
		return ;
	}

	// 프로세스의 fdt를 검색해서 파일 객체를 찾음.
	def_thread *curr = thread_current();
	struct file **fdt = curr->fdt;
	struct file *file = fdt[fd];

	if(file == NULL){
		return ;
	}else{
		file_seek(file,position);
	}
}

// 파일의 현재위치를 반환하는 함수.
unsigned tell (int fd){
	if(fd < 3){
		return 0;
	}

	// 프로세스의 fdt를 검색해서 파일 객체를 찾음.
	def_thread *curr = thread_current();
	struct file **fdt = curr->fdt;
	struct file *file = fdt[fd];

	if(file == NULL){
		return 0;
	}else{
		return file_tell(file);
	}
}

void close (int fd){
	def_thread *curr = thread_current();
	struct file **fdt = curr->fdt;
	struct file *file = fdt[fd];

	file_close(file);
}

tid_t fork (const char *thread_name){}

bool check_address(const char *addr){
	def_thread *curr = thread_current();
	if(!is_user_vaddr(addr) || addr == NULL){
		exit(-1);
		return false;
	}
	return true;
}