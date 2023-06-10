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

void check_address(void* addr);
struct file* find_file_using_fd(int fd);
int insert_file_to_fdt(struct file *file);
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
			break;
		case SYS_EXIT:
			exit(f->R.rdi);
			break;
		case SYS_FORK:
			f->R.rax = fork(f->R.rdi);
			break;
		case SYS_EXEC:
			f->R.rax = exec(f->R.rdi);
			break;
		case SYS_WAIT:
			f->R.rax = wait(f->R.rdi);
			break;
		case SYS_CREATE:
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = remove(f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = open(f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
			break;
		case SYS_READ:
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL:
			f->R.rax = tell(f->R.rdi);
			break;
		case SYS_CLOSE:
			close(f->R.rdi);
			break;
	}
}

void halt (void){
	power_off();
}

void exit (int status){
	def_thread *curr = thread_current();
	curr->exit_status = status;
	printf("%s: exit(%d)\n", curr->name, status);
	thread_exit();
}

int exec (const char *cmd_line){}
int wait (tid_t pid){}

bool create (const char *file, unsigned initial_size){
	lock_acquire(&filesys_lock);
	check_address(file);
	bool boolean = filesys_create(file, initial_size);
	lock_release(&filesys_lock);
	return boolean;
}

bool remove (const char *file){
	check_address(file);
	return filesys_remove(file);
}


int open (const char *file){
	check_address(file);

	lock_acquire(&filesys_lock);
	struct file *f = filesys_open(file);

	if(f == NULL){
		lock_release(&filesys_lock);
		return -1;
	}

	int fd = insert_file_to_fdt(f);

	if(fd == -1){
		file_close(f);
	}
	lock_release(&filesys_lock);
	return fd;
}

// 수정
int filesize (int fd){
	struct file *f = find_file_using_fd(fd);

	if(f == NULL){
		return -1;
	}
	return file_length(f);
}

int read (int fd, void *buffer, unsigned size){
	check_address(buffer);

	uint8_t key;
	int read_size;	
	struct file* f = find_file_using_fd(fd);

	// fd가 0일 때(파일 끝에서 시도하는 경우), input_getc()로 키보드로부터 바이트를 읽는다.
	lock_acquire(&filesys_lock);
	if(fd == 0){
		key = input_getc();
		lock_release(&filesys_lock);
		return key;
	}else if(fd == 1) {// 해당 파일을 읽을 수 있다면 file_read()로 바이트를 읽는다. 읽을 수 없다면 -1 반환
		lock_release(&filesys_lock);
		return -1;
	}else {
		read_size = file_read(f, buffer, size);
		lock_release(&filesys_lock);
	}	
	return read_size;
}

int write (int fd, const void *buffer, unsigned size) {
	check_address(buffer);
	int write_size;
	struct file *f = find_file_using_fd(fd);

	lock_acquire(&filesys_lock);
	if(fd == 1) {
		putbuf(buffer, size);
		write_size = size;
		lock_release(&filesys_lock);
	}else if(fd == 0) {
		lock_release(&filesys_lock);
		return -1;
	}else {
		write_size = file_write(f, buffer, size);
		lock_release(&filesys_lock);
	}
	return write_size;
}


// 파일을 특정위치로 이동시키는 함수.
void seek (int fd, unsigned position){
	struct file* f = find_file_using_fd(fd);

	if(f == NULL){
		return ;
	}

	file_seek(f, position);
}

// 파일의 현재위치를 반환하는 함수.
unsigned tell (int fd){
	struct file* f = find_file_using_fd(fd);
	check_address(f);

	if(f == NULL){
		return ;
	}
	return file_tell(f);
}

void close (int fd){
	struct file* f = find_file_using_fd(fd);
	if(f == NULL){
		return ;
	}

	file_close(f);
}

tid_t fork (const char *thread_name){}

// 주소가 유효한지 체크하는 함수.
void check_address(void* addr){
	if(!is_user_vaddr(addr) || addr == NULL){
		exit(-1);
	}
}

// fd를 이용해서 fdt에서 파일을 찾는 함수.
struct file* find_file_using_fd(int fd){
	if(fd < 0 || fd >= 64){
		return NULL;
	}
	def_thread *curr = thread_current();
	struct file **fdt = curr->fdt;
	struct file *file = fdt[fd];

	return file;
}

// fdt에 파일을 삽입하는 함수.
int insert_file_to_fdt(struct file *file){
	def_thread *curr = thread_current();
	struct file **fdt = curr->fdt;
	int fd = curr->next_fd;

	while(curr->fdt[fd] != NULL && fd < 64){
		fd++;
	}

	if(fd >= 64){
		return -1;
	}

	curr->next_fd = fd;
	fdt[fd] = file;

	return fd;
}