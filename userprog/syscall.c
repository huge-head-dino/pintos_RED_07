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

/*
lock_init(&filesys_lock);    ---> lock을 초기화
lock_acquire(&filesys_lock); ---> 다른 프로세스가 접근하지 못하도록 lock획득
lock_release(&filesys_lock); ---> 일을 마치고 나서 lock 반환.
*/

// pintOS 종료
void halt (void){
	power_off();
}

// 프로세스 종료
void exit (int status){
	def_thread *curr = thread_current();
	curr->exit_status = status;
	printf("%s: exit(%d)\n", curr->name, status);
	thread_exit();
}

// 인자로 주어지는 initial_size의 크기를 가지는 파일 생성.
bool create (const char *file, unsigned initial_size){
	lock_acquire(&filesys_lock);
	check_address(file);
	bool boolean = filesys_create(file, initial_size);
	lock_release(&filesys_lock);
	return boolean;
}

// 인자로 받은 file과 동일한 이름의 파일을 제거.
bool remove (const char *file){
	check_address(file);
	return filesys_remove(file);
}

// 파일을 여는 시스템 콜
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

// 파일의 크기를 알려주는 시스템 콜
int filesize (int fd){
	struct file *f = find_file_using_fd(fd);

	if(f == NULL){
		return -1;
	}
	return file_length(f);
}

// 열린 파일의 데이터를 읽는 시스템 콜
int read (int fd, void *buffer, unsigned size){// 인자로 받은 size는 읽을 데이터의 크기
	check_address(buffer); // file의 주소가 유효한 지 체크했듯이, 읽어들일 버퍼 또한 유효한지 체크

	uint8_t key;
	int read_size;	
	struct file* f = find_file_using_fd(fd);

	// fd가 0일 때(파일 끝에서 시도하는 경우), input_getc()로 키보드로부터 바이트를 읽는다.
	lock_acquire(&filesys_lock);
	if(fd == 0){ // STDIN일 때
		key = input_getc(); // 키보드로 입력 받은 문자를 반환하고 버퍼에 저장.
		lock_release(&filesys_lock);
		return key;
	}else if(fd == 1) {// STDOUT일 때
		lock_release(&filesys_lock);
		return -1;
	}else {// 그 외 데이터를 읽을 수 있는 파일일 때
		read_size = file_read(f, buffer, size);
		lock_release(&filesys_lock);
	}	
	return read_size;
}

// 열린 파일의 데이터를 기록하는 시스템 콜
int write (int fd, const void *buffer, unsigned size) { // 인자로 받은 size는 기록할 데이터 크기
	check_address(buffer);// file의 주소가 유요한 지 체크했듯이, 데이터를 기록할 버퍼 또한 유효한지 체크
	int write_size;
	struct file *f = find_file_using_fd(fd);

	lock_acquire(&filesys_lock);
	if(fd == 1) { // STDOUT일 때
		putbuf(buffer, size); // 버퍼에 저장된 문자열을 화면에 출력
		write_size = size;
		lock_release(&filesys_lock);
	}else if(fd == 0) { // STDIN일 때
		lock_release(&filesys_lock);
		return -1;
	}else { // 데이터를 기록할 수 있는 파일일 때
		write_size = file_write(f, buffer, size);
		lock_release(&filesys_lock);
	}
	return write_size;
}

// 열린 파일을 특정위치로 이동시키는 시스템 콜
void seek (int fd, unsigned position){
	struct file* f = find_file_using_fd(fd);

	if(f == NULL){
		return ;
	}

	file_seek(f, position);
}

// 열린 파일의 위치를 알려주는 시스템 콜
unsigned tell (int fd){
	struct file* f = find_file_using_fd(fd);
	check_address(f);

	if(f == NULL){
		return ;
	}
	return file_tell(f);
}

// 열린 파일을 닫는 시스템 콜
void close (int fd){
	def_thread *curr = thread_current();
	struct file** fdt = curr->fdt;
	struct file* f = find_file_using_fd(fd);

	if(f == NULL){ // 해당 파일이 비어있다면 그대로 종료.
		return ;
	}

	if(fd <= 3 || fd >= 64){ // 해당 파일이 STDIO,STDERR이거나 fdt의 인덱스 값을 벗어나면 종료.
		return;
	}
	file_close(f); // malloc, calloc, realloc을 써서 fdt의 해당 파일의 메모리를 동적 할당한 경우 free함수를 통해 메모리를 반환해주지만, 우리는 동적할당을 해준 적이 없음.
	fdt[fd] = NULL; // 그러므로 fdt의 해당 fd에 위치하고 있던 파일을 NULL값으로 명시적으로 할당해야 함.
}

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

tid_t fork (const char *thread_name){}
int exec (const char *cmd_line){}
int wait (tid_t pid){}