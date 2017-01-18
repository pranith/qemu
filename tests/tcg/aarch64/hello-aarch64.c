#include <asm/unistd.h>

static int __internal_syscall1(int nr, int arg1) {
  register int x8 asm("x8") = nr;
  register int x0 asm("x0") = arg1;
  asm volatile("svc 0"
		: "=r"(x0)
		: "r"(x8)
		: "memory", "cc");
  return x0;
}

static int __internal_syscall3(int nr, int arg1, long arg2, long arg3) {
  register int x8 asm("x8") = nr;
  register int x0 asm("x0") = arg1;
  register int x1 asm("x1") = arg2;
  register int x2 asm("x2") = arg3;
  asm volatile("svc 0"
		: "=r"(x0)
		: "r"(x8), "0"(x0), "r"(x1), "r"(x2)
		: "memory", "cc");
  return x0;
}

int main()
{
	char *text = "Hello World\n";
	__internal_syscall3(__NR_write, 1, (long)text, 12);
	__internal_syscall1(__NR_exit, 0);

	return 0;
}
