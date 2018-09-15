#ifndef _QSIM_MAGIC_H
#define _QSIM_MAGIC_H

#if defined(__arm__) || defined(__aarch64__)

#define qsim_magic_enable()				\
	asm volatile("msr pmuserenr_el0, %0" :: "r" (0xaaaaaaaa));
#define qsim_magic_disable() 				\
	asm volatile("msr pmuserenr_el0, %0" :: "r" (0xfa11dead));

#elif defined(__i386__) || defined(__x86_64__)

#define qsim_magic_enable()				\
	asm volatile("cpuid;"::"a"(0xaaaaaaaa):"ebx","ecx","edx");
#define qsim_magic_disable()				\
	asm volatile("cpuid;"::"a"(0xfa11dead):"ebx","ecx","edx");

#endif

#endif /* _QSIM_MAGIC_H */
