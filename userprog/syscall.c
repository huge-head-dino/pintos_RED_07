#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

// -------------------------------------macro function------------------------------------------//
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
// ----------------------------------------------------------------------------------------//

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
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	switch (f->R.rax)
	{
	case SYS_HALT:
		halt();
		break;
	
	case SYS_EXIT:		
		exit(f->R.rdi);
		break;
	
	case SYS_FORK:
		/* code */
		break;
	
	case SYS_EXEC:
		/* code */
		break;
	
	case SYS_WAIT:
		/* code */
		break;
	
	case SYS_CREATE:
		create();
		break;
	
	case SYS_REMOVE:
		remove();
		break;
	
	case SYS_OPEN:
		open();
		break;
	
	case SYS_FILESIZE:
		/* code */
		break;
	
	case SYS_READ:
		/* code */
		break;
	
	case SYS_WRITE:
		/* code */
		break;
	
	case SYS_SEEK:
		/* code */
		break;
	
	case SYS_TELL:
		/* code */
		break;
	
	case SYS_CLOSE:
		/* code */
		break;
	
	default:
		break;
	}
	printf ("system call!\n");
	thread_exit ();
}

void halt(void) {
	power_off();
}

void exit(int status) {
	thread_exit();
	// 커널에 상태를 리턴하면서 종료합니다. 미완
	printf("Name of process: exit(%d)", status);
}

tid_t fork (const char *thread_name) {
	
}
int exec (const char *cmd_line) {

}

int wait (tid_t pid) {

}

bool create (const char *file, unsigned initial_size) {
	if(filesys_create(file, initial_size)) return 1;
	else return 0;
}
bool remove (const char *file) {
	if(filesys_remove(file)) return 1;
	else return 0;
}

int open (const char *file) {
	struct file *open_file = filesys_open(file);
}

int filesize (int fd) {

}
int read (int fd, void *buffer, unsigned size) {

}
int write (int fd, const void *buffer, unsigned size) {

}
void seek (int fd, unsigned position) {

}
unsigned tell (int fd) {

}
void close (int fd) {

}