
#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <ucontext.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <asm/perf_regs.h>
#include <pthread.h>
long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags) {
  return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

pid_t gettid() {
  return syscall(__NR_gettid);
}

int perf_fd[32];
void *our_mmap[32];
static volatile int i = 0, j = 0;
static long long prev_head = 0;
static int quiet = 0;
static long long global_sample_type;
static long long global_sample_regs_user;
//int test0 __attribute__ ((aligned(64)));
//int test1 __attribute__ ((aligned(64)));
int test0,test1;
static long long readtime = 0;
static long long mmap_count = 0;
//static long long offset = 0;
#define MMAP_DATA_SIZE 8
//#define max_read 300000000
#define DEBUG 1

int sample_type= PERF_SAMPLE_IP | PERF_SAMPLE_TID | 
                  PERF_SAMPLE_ADDR | PERF_SAMPLE_DATA_SRC | PERF_SAMPLE_CPU;
//int sample_type= PERF_SAMPLE_ADDR | PERF_SAMPLE_CPU;

					// | PERF_SAMPLE_CALLCHAIN | PERF_SAMPLE_PERIOD;


int read_format= PERF_FORMAT_GROUP;
//                 PERF_FORMAT_ID |
//                 PERF_FORMAT_TOTAL_TIME_ENABLED |
//                 PERF_FORMAT_TOTAL_TIME_RUNNING;


void enable_trace(int fd) {
  // Start the event
  if(ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) == -1) {
    fprintf(stderr, "Failed to enable perf event: %s\n", strerror(errno));
    abort();
  }
/*	if(fcntl(fd, F_SETFL, O_RDONLY|O_NONBLOCK)!=0) {
	fprintf(stderr,"Failed to enable perf event!\n");
	abort();
	}*/
}

void disable_trace(int fd) {
  // Start the event
  if(ioctl(fd, PERF_EVENT_IOC_DISABLE, 0) == -1) {
    fprintf(stderr, "Failed to disable perf event: %s\n", strerror(errno));
    abort();
  }
}


#if DEBUG

#define NUM_REGS  PERF_REG_X86_64_MAX
static char reg_names[NUM_REGS][8]=
      {"RAX","RBX","RCX","RDX","RSI","RDI","RBP","RSP",
       "RIP","RFLAGS","CS","SS","DS","ES","FS","GS",
       "R8","R9","R10","R11","R12","R13","R14","R15"};
/* Urgh who designed this interface */
static int handle_struct_read_format(unsigned char *sample,
             int read_format,
             void *validation,
             int quiet) {

 // int i;
	int offset=0, i;
  if (read_format & PERF_FORMAT_GROUP) {
    long long nr,time_enabled,time_running;

    memcpy(&nr,&sample[offset],sizeof(long long));
    if (!quiet) printf("\t\tNumber: %lld ",nr);
    offset+=8;

    if (read_format & PERF_FORMAT_TOTAL_TIME_ENABLED) {
      memcpy(&time_enabled,&sample[offset],sizeof(long long));
      if (!quiet) printf("enabled: %lld ",time_enabled);
      offset+=8;
    }
    if (read_format & PERF_FORMAT_TOTAL_TIME_RUNNING) {
      memcpy(&time_running,&sample[offset],sizeof(long long));
      if (!quiet) printf("running: %lld ",time_running);
      offset+=8;
    }

    if (!quiet) printf("\n");

    for(i=0;i<nr;i++) {
      long long value, id;

      memcpy(&value,&sample[offset],sizeof(long long));
      if (!quiet) printf("\t\t\tValue: %lld ",value);
      offset+=8;

      if (read_format & PERF_FORMAT_ID) {
        memcpy(&id,&sample[offset],sizeof(long long));
        if (!quiet) printf("id: %lld ",id);
        offset+=8;
      }

      if (!quiet) printf("\n");
    }
  }
  else {

    long long value,time_enabled,time_running,id;

    memcpy(&value,&sample[offset],sizeof(long long));
    if (!quiet) printf("\t\tValue: %lld ",value);
    offset+=8;

    if (read_format & PERF_FORMAT_TOTAL_TIME_ENABLED) {
      memcpy(&time_enabled,&sample[offset],sizeof(long long));
      if (!quiet) printf("enabled: %lld ",time_enabled);
      offset+=8;
    }
    if (read_format & PERF_FORMAT_TOTAL_TIME_RUNNING) {
      memcpy(&time_running,&sample[offset],sizeof(long long));
      if (!quiet) printf("running: %lld ",time_running);
      offset+=8;
    }
    if (read_format & PERF_FORMAT_ID) {
      memcpy(&id,&sample[offset],sizeof(long long));
      if (!quiet) printf("id: %lld ",id);
      offset+=8;

    }
    if (!quiet) printf("\n");
  }

  return offset;
}

static int print_regs(int quiet,long long abi,long long reg_mask,
    unsigned char *data) {

  //int return_offset=0;
  int return_offset=0;
  int num_regs=NUM_REGS;
  int i;
  unsigned long long reg_value;

  if (!quiet) printf("\t\tReg mask %llx\n",reg_mask);
  for(i=0;i<64;i++) {
    if (reg_mask&1ULL<<i) {
      if (!quiet) {
        memcpy(&reg_value,&data[return_offset],8);
        if (i<num_regs) {
          printf("\t\t%s : ",reg_names[i]);
        }
        else {
          printf("\t\t??? : ");
        }

        printf("%llx\n",reg_value);
      }
      return_offset+=8;
    }
  }

  return return_offset;
}



int getpagesize() {
//	return 8192;
	return 4096;
}

long long perf_mmap_read( void *our_mmap, int mmap_size,
                    long long prev_head,
		    int sample_type, int read_format, long long reg_mask,
		    void *validate,
		    int quiet, int *events_read ) {

	struct perf_event_mmap_page *control_page = (struct perf_event_mmap_page * )our_mmap;
	long long head, offset;
	int i,size;
	long long bytesize,prev_head_wrap;
	struct timeval timeS, timeF;
	long long timeuse;
	unsigned char *data;

//	void *data_mmap = (void *)((size_t)+getpagesize());
	void *data_mmap= (void *)((size_t)our_mmap+getpagesize());

	if (mmap_size==0) return 0;

	if (control_page==NULL) {
		fprintf(stderr,"ERROR mmap page NULL\n");
		return -1;
	}

	head=control_page->data_head;
	//rmb(); /* Must always follow read of data_head */

	size=head-prev_head;
	//prev_head+=size;
	//printf("size = %d\n\n\n",size);
	//gettimeofday(&timeS,NULL);

	printf("Head: %lld Prev_head=%lld\n",head,prev_head);
	printf("%d new bytes\n",size);

	bytesize=mmap_size*getpagesize();

	if (size>bytesize) {
		printf("error!  we overflowed the mmap buffer %d>%lld bytes\n",
			size,bytesize);
	}

	data= (unsigned char *)malloc(bytesize);
	if (data==NULL) {
		return -1;
	}

	prev_head_wrap=prev_head%bytesize;
	    
/*	printf("Copying %d bytes from %d to %d\n",
                bytesize-prev_head_wrap,prev_head_wrap,0);
        memcpy(data,(unsigned char*)data_mmap,
                size);
        printf("Copying %d bytes from %d to %d\n",
                prev_head_wrap,0,bytesize-prev_head_wrap);
*/
	 memcpy(data,(unsigned char*)data_mmap + prev_head_wrap,
                bytesize-prev_head_wrap);
		
	   memcpy(data+(bytesize-prev_head_wrap),(unsigned char *)data_mmap,
                prev_head_wrap); 

	struct perf_event_header *event;


	offset=0;
	if (events_read) *events_read=0;
	     long long iter = offset;
                        while(iter < (offset + size)) {
                                long long value;
                                memcpy(&value, &data[iter], sizeof(long long));
                                if (!quiet) printf("\t offset %llx: %llx\n", iter, value);
                                iter += 8;
                        }



	while(offset<size) {

		//printf("Offset %d Size %d\n",offset,size);
		event = ( struct perf_event_header * ) & data[offset];

		/********************/
		/* Print event Type */
		/********************/

//#if 0
		if (!quiet) {
			switch(event->type) {
				case PERF_RECORD_MMAP:
					printf("PERF_RECORD_MMAP"); break;
				case PERF_RECORD_LOST:
					printf("PERF_RECORD_LOST"); break;
				case PERF_RECORD_COMM:
					printf("PERF_RECORD_COMM"); break;
				case PERF_RECORD_EXIT:
					printf("PERF_RECORD_EXIT"); break;
				case PERF_RECORD_THROTTLE:
					printf("PERF_RECORD_THROTTLE"); break;
				case PERF_RECORD_UNTHROTTLE:
					printf("PERF_RECORD_UNTHROTTLE"); break;
				case PERF_RECORD_FORK:
					printf("PERF_RECORD_FORK"); break;
				case PERF_RECORD_READ:
					printf("PERF_RECORD_READ"); break;
				case PERF_RECORD_SAMPLE:
					printf("PERF_RECORD_SAMPLE [%x]",sample_type); break;
				case PERF_RECORD_MMAP2:
					printf("PERF_RECORD_MMAP2"); break;
				default: printf("UNKNOWN %d",event->type); break;
			}

			printf(", MISC=%d (",event->misc);
			switch(event->misc & PERF_RECORD_MISC_CPUMODE_MASK) {
				case PERF_RECORD_MISC_CPUMODE_UNKNOWN:
					printf("PERF_RECORD_MISC_CPUMODE_UNKNOWN"); break; 
				case PERF_RECORD_MISC_KERNEL:
					printf("PERF_RECORD_MISC_KERNEL"); break;
				case PERF_RECORD_MISC_USER:
					printf("PERF_RECORD_MISC_USER"); break;
				case PERF_RECORD_MISC_HYPERVISOR:
					printf("PERF_RECORD_MISC_HYPERVISOR"); break;
				case PERF_RECORD_MISC_GUEST_KERNEL:
					printf("PERF_RECORD_MISC_GUEST_KERNEL"); break;
				case PERF_RECORD_MISC_GUEST_USER:
					printf("PERF_RECORD_MISC_GUEST_USER"); break;
				default:
					printf("Unknown %d!\n",event->misc); break;
			}

			/* Both have the same value */
			if (event->misc & PERF_RECORD_MISC_MMAP_DATA) {
				printf(",PERF_RECORD_MISC_MMAP_DATA or PERF_RECORD_MISC_COMM_EXEC ");
			}

			if (event->misc & PERF_RECORD_MISC_EXACT_IP) {
				printf(",PERF_RECORD_MISC_EXACT_IP ");
			}

			if (event->misc & PERF_RECORD_MISC_EXT_RESERVED) {
				printf(",PERF_RECORD_MISC_EXT_RESERVED ");
			}

			printf("), Size=%d\n",event->size);
		}
//#endif
		offset+=8; /* skip header */

		/***********************/
		/* Print event Details */
		/***********************/

		switch(event->type) {

		/* Lost */
		case PERF_RECORD_LOST: {
			long long id,lost;
			memcpy(&id,&data[offset],sizeof(long long));
			if (!quiet) printf("\tID: %lld\n",id);
			offset+=8;
			memcpy(&lost,&data[offset],sizeof(long long));
			if (!quiet) printf("\tLOST: %lld\n",lost);
			offset+=8;
			}
			break;
	
		/* COMM */
		case PERF_RECORD_COMM: {
			int pid,tid,string_size;
			char *string;

			memcpy(&pid,&data[offset],sizeof(int));
			if (!quiet) printf("\tPID: %d\n",pid);
			offset+=4;
			memcpy(&tid,&data[offset],sizeof(int));
			if (!quiet) printf("\tTID: %d\n",tid);
			offset+=4;
		
			/* FIXME: sample_id handling? */

			/* two ints plus the 64-bit header */
			string_size=event->size-16;
			string=(char *)calloc(string_size,sizeof(char));
			memcpy(string,&data[offset],string_size);
			if (!quiet) printf("\tcomm: %s\n",string);
			offset+=string_size;
			if (string) free(string);
			}
			break;
		
		/* Fork */
		case PERF_RECORD_FORK: {
			int pid,ppid,tid,ptid;
			long long fork_time;

			memcpy(&pid,&data[offset],sizeof(int));
			if (!quiet) printf("\tPID: %d\n",pid);
			offset+=4;
			memcpy(&ppid,&data[offset],sizeof(int));
			if (!quiet) printf("\tPPID: %d\n",ppid);
			offset+=4;
			memcpy(&tid,&data[offset],sizeof(int));
			if (!quiet) printf("\tTID: %d\n",tid);
			offset+=4;
			memcpy(&ptid,&data[offset],sizeof(int));
			if (!quiet) printf("\tPTID: %d\n",ptid);
			offset+=4;
			memcpy(&fork_time,&data[offset],sizeof(long long));
			if (!quiet) printf("\tTime: %lld\n",fork_time);
			offset+=8;
			memcpy(&tid,&data[offset],sizeof(int));
                        if (!quiet) printf("\tTID: %d\n",tid);
                        offset+=4;
                        memcpy(&ptid,&data[offset],sizeof(int));
                        if (!quiet) printf("\tPTID: %d\n",ptid);
                        offset+=4;
                        memcpy(&fork_time,&data[offset],sizeof(long long));
                        if (!quiet) printf("\tTime: %lld\n",fork_time);
                        offset+=8;

			}
			break;
		
		/* mmap */
		case PERF_RECORD_MMAP: {
			int pid,tid,string_size;
			long long address,len,pgoff;
			char *filename;

			memcpy(&pid,&data[offset],sizeof(int));
			if (!quiet) printf("\tPID: %d\n",pid);
			offset+=4;
			memcpy(&tid,&data[offset],sizeof(int));
			if (!quiet) printf("\tTID: %d\n",tid);
			offset+=4;
			memcpy(&address,&data[offset],sizeof(long long));
			if (!quiet) printf("\tAddress: %llx\n",address);
			offset+=8;
			memcpy(&len,&data[offset],sizeof(long long));
			if (!quiet) printf("\tLength: %llx\n",len);
			offset+=8;
			memcpy(&pgoff,&data[offset],sizeof(long long));
			if (!quiet) printf("\tPage Offset: %llx\n",pgoff);
			offset+=8;

			string_size=event->size-40;
			filename=(char *)calloc(string_size,sizeof(char));
			memcpy(filename,&data[offset],string_size);
			if (!quiet) printf("\tFilename: %s\n",filename);
			offset+=string_size;
			if (filename) free(filename);

			}
			break;
		
		/* mmap2 */
		case PERF_RECORD_MMAP2: {
			int pid,tid,string_size;
			long long address,len,pgoff;
			int major,minor;
			long long ino,ino_generation;
			int prot,flags;
			char *filename;

			memcpy(&pid,&data[offset],sizeof(int));
			if (!quiet) printf("\tPID: %d\n",pid);
			offset+=4;
			memcpy(&tid,&data[offset],sizeof(int));
			if (!quiet) printf("\tTID: %d\n",tid);
			offset+=4;
			memcpy(&address,&data[offset],sizeof(long long));
			if (!quiet) printf("\tAddress: %llx\n",address);
			offset+=8;
			memcpy(&len,&data[offset],sizeof(long long));
			if (!quiet) printf("\tLength: %llx\n",len);
			offset+=8;
			memcpy(&pgoff,&data[offset],sizeof(long long));
			if (!quiet) printf("\tPage Offset: %llx\n",pgoff);
			offset+=8;
			memcpy(&major,&data[offset],sizeof(int));
			if (!quiet) printf("\tMajor: %d\n",major);
			offset+=4;
			memcpy(&minor,&data[offset],sizeof(int));
			if (!quiet) printf("\tMinor: %d\n",minor);
			offset+=4;
			memcpy(&ino,&data[offset],sizeof(long long));
			if (!quiet) printf("\tIno: %llx\n",ino);
			offset+=8;
			memcpy(&ino_generation,&data[offset],sizeof(long long));
			if (!quiet) printf("\tIno generation: %llx\n",ino_generation);
			offset+=8;
			memcpy(&prot,&data[offset],sizeof(int));
			if (!quiet) printf("\tProt: %d\n",prot);
			offset+=4;
			memcpy(&flags,&data[offset],sizeof(int));
			if (!quiet) printf("\tFlags: %d\n",flags);
			offset+=4;

			string_size=event->size-72;
			filename=(char *)calloc(string_size,sizeof(char));
			memcpy(filename,&data[offset],string_size);
			if (!quiet) printf("\tFilename: %s\n",filename);
			offset+=string_size;
			if (filename) free(filename);

			}
			break;
		
		/* Exit */
		case PERF_RECORD_EXIT: {
			int pid,ppid,tid,ptid;
			long long fork_time;

			memcpy(&pid,&data[offset],sizeof(int));
			if (!quiet) printf("\tPID: %d\n",pid);
			offset+=4;
			memcpy(&ppid,&data[offset],sizeof(int));
			if (!quiet) printf("\tPPID: %d\n",ppid);
			offset+=4;
			memcpy(&tid,&data[offset],sizeof(int));
			if (!quiet) printf("\tTID: %d\n",tid);
			offset+=4;
			memcpy(&ptid,&data[offset],sizeof(int));
			if (!quiet) printf("\tPTID: %d\n",ptid);
			offset+=4;
			memcpy(&fork_time,&data[offset],sizeof(long long));
			if (!quiet) printf("\tTime: %lld\n",fork_time);
			offset+=8;
			}
			break;
		
		/* Sample */
 			 case PERF_RECORD_SAMPLE: {
               #if 0
                        long long iter = offset-8;
                        while(iter < (offset + size)) {
                                long long value;
                                memcpy(&value, &data[iter], sizeof(long long));
                                if (!quiet) printf("\t offset %llx: %llx\n", iter, value);
                                iter += 8;
                        }
                #endif
                        offset-=8;
                        int pid, tid, cpu, res;
                        long long ip;
                        long long addr;
                        int type;
			int misc;
			int size;
                        long long time;
                        long long sample_id;
                        long long sample_stream_id;
                        long long weight;
                        long long src;
			 if(sample_type & PERF_SAMPLE_READ) {
                                int length;
                                if(!quiet) printf("\tPERF_SAMPLE_READ, read_format\n");
                                length=handle_struct_read_format(&data[offset],read_format,validate,quiet);
                                if(length>=0) offset+=length;
                        }
                        offset+=8;
                        memcpy(&ip, &data[offset],sizeof(long long));
                        if(!quiet) printf("\tPERF_SAMPLE_IP: %llx\n", ip);
                        offset+=8;
                        memcpy(&pid,&data[offset],sizeof(int));
                        memcpy(&tid,&data[offset+4],sizeof(int));
                        if (!quiet) printf("\tPERF_SAMPLE_TID, pid: %d  tid %d\n",pid,tid);
                        offset+=8;
                        memcpy(&time,&data[offset],sizeof(long long));
                        if (!quiet) printf("\tPERF_SAMPLE_TIME: %lld\n",time);
                        offset+=8;
                        memcpy(&addr,&data[offset],sizeof(long long));
                        if (!quiet) printf("\tPERF_SAMPLE_ADDR, addr: %llx. Offset %llx\n",addr, offset);
                        offset+=8;
                        //memcpy(&sample_id,&data[offset],sizeof(long long));
                        //if (!quiet) printf("\tPERF_SAMPLE_ID, sample_id: %lld. Offset %llx\n",sample_id, offset);
                        //offset+=8;
                        //memcpy(&sample_stream_id,&data[offset],sizeof(long long));
                        //if (!quiet) printf("\tPERF_SAMPLE_STREAM_ID, sample_stream_id: %lld\n",sample_stream_id);
                        //offset+=8;
                        memcpy(&cpu,&data[offset],sizeof(int));
                        memcpy(&res,&data[offset+4],sizeof(int));
                        if (!quiet) printf("\tPERF_SAMPLE_CPU, cpu: %d  res %d\n",cpu,res);
                        offset+=8;
                        //offset+=8;
                        memcpy(&weight,&data[offset],sizeof(long long));
			if(!quiet) printf("\tPERF_SAMPLE_WEIGHT: %lld\n",weight);
			 offset+=8;
			//memcpy(&cpu,&data[offset],sizeof(int));
			//memcpy(&res,&data[offset+4],sizeof(int));
			//if (!quiet) printf("\tPERF_SAMPLE_CPU, cpu: %d  res %d\n",cpu,res);
						//offset+=8;
                        
			//if (!quiet) printf("\n");
                        memcpy(&src,&data[offset],sizeof(long long));
                        if (!quiet) printf("\tPERF_SAMPLE_DATA_SRC, Raw: %llx\n",src);
                        offset+=8;
                        if (!quiet) {
                                        if (src!=0) printf("\t\t");
                                        if (src & (PERF_MEM_OP_NA<<PERF_MEM_OP_SHIFT))
                                                printf("Op Not available \n");
                                        if (src & (PERF_MEM_OP_LOAD<<PERF_MEM_OP_SHIFT))
                                                printf("Load \n");
                                        if (src & (PERF_MEM_OP_STORE<<PERF_MEM_OP_SHIFT))
                                                printf("Store \n");
                                        if (src & (PERF_MEM_OP_PFETCH<<PERF_MEM_OP_SHIFT))
                                                printf("Prefetch \n");
                                        if (src & (PERF_MEM_OP_EXEC<<PERF_MEM_OP_SHIFT))
                                                printf("Executable code \n");

                                        if (src & (PERF_MEM_LVL_NA<<PERF_MEM_LVL_SHIFT))
                                                printf("Level Not available \n");
                                        if (src & (PERF_MEM_LVL_HIT<<PERF_MEM_LVL_SHIFT))
                                                printf("Hit \n");
                                        if (src & (PERF_MEM_LVL_MISS<<PERF_MEM_LVL_SHIFT))
                                                printf("Miss \n");
                                        if (src & (PERF_MEM_LVL_L1<<PERF_MEM_LVL_SHIFT))
                                                printf("L1 cache \n");
                                        if (src & (PERF_MEM_LVL_LFB<<PERF_MEM_LVL_SHIFT))
                                                printf("Line fill buffer \n");
                                        if (src & (PERF_MEM_LVL_L2<<PERF_MEM_LVL_SHIFT))
                                                printf("L2 cache \n");
                                        if (src & (PERF_MEM_LVL_L3<<PERF_MEM_LVL_SHIFT))
                                                printf("L3 cache \n");
                                        if (src & (PERF_MEM_LVL_LOC_RAM<<PERF_MEM_LVL_SHIFT))
                                                printf("Local DRAM \n");
                                        if (src & (PERF_MEM_LVL_REM_RAM1<<PERF_MEM_LVL_SHIFT))
                                                printf("Remote DRAM 1 hop \n");
                                        if (src & (PERF_MEM_LVL_REM_RAM2<<PERF_MEM_LVL_SHIFT))
                                                printf("Remote DRAM 2 hops \n");
                                        if (src & (PERF_MEM_LVL_REM_CCE1<<PERF_MEM_LVL_SHIFT))
                                                printf("Remote cache 1 hop \n");
                                        if (src & (PERF_MEM_LVL_REM_CCE2<<PERF_MEM_LVL_SHIFT))
                                                printf("Remote cache 2 hops \n");
                                        if (src & (PERF_MEM_LVL_IO<<PERF_MEM_LVL_SHIFT))
                                                printf("I/O memory \n");

					if (src & (PERF_MEM_SNOOP_NA<<PERF_MEM_SNOOP_SHIFT))
						printf("Not available \n");
					if (src & (PERF_MEM_SNOOP_NONE<<PERF_MEM_SNOOP_SHIFT))
						printf("No snoop \n");
					if (src & (PERF_MEM_SNOOP_HIT<<PERF_MEM_SNOOP_SHIFT))
						printf("Snoop hit \n");
					if (src & (PERF_MEM_SNOOP_MISS<<PERF_MEM_SNOOP_SHIFT))
						printf("Snoop miss \n");
					if (src & (PERF_MEM_SNOOP_HITM<<PERF_MEM_SNOOP_SHIFT))
						printf("Snoop hit modified \n");

					if (src & (PERF_MEM_LOCK_NA<<PERF_MEM_LOCK_SHIFT))
						printf("Not available \n");
					if (src & (PERF_MEM_LOCK_LOCKED<<PERF_MEM_LOCK_SHIFT))
						printf("Locked transaction \n");

					if (src & (PERF_MEM_TLB_NA<<PERF_MEM_TLB_SHIFT))
						printf("Not available \n");
					if (src & (PERF_MEM_TLB_HIT<<PERF_MEM_TLB_SHIFT))
						printf("Hit \n");
					if (src & (PERF_MEM_TLB_MISS<<PERF_MEM_TLB_SHIFT))
						printf("Miss \n");
					if (src & (PERF_MEM_TLB_L1<<PERF_MEM_TLB_SHIFT))
						printf("Level 1 TLB \n");
					if (src & (PERF_MEM_TLB_L2<<PERF_MEM_TLB_SHIFT))
						printf("Level 2 TLB \n");
					if (src & (PERF_MEM_TLB_WK<<PERF_MEM_TLB_SHIFT))
						printf("Hardware walker \n");
					if (src & (PERF_MEM_TLB_OS<<PERF_MEM_TLB_SHIFT))
						printf("OS fault handler \n");
				}

				if (!quiet) printf("\n");
			

			
			}
			break;
			if (!quiet)
			 printf("\tType: %d\n",event->type);
		}
		offset+=size;
		if (events_read) (*events_read)++;
	}
//	offset+=size;
	control_page->data_tail=head;

	free(data);
	/*gettimeofday(&timeF,NULL);
	timeuse = 1000000*(timeF.tv_sec-timeS.tv_sec)+(timeF.tv_usec-timeS.tv_usec);
	readtime = readtime + timeuse;
	fprintf(stderr, "MMAP_READ %lld takes %lld Useconds.\n", mmap_count, timeuse);
	*/
	mmap_count++;
	return head;

}

#endif

// The iterator variable
void fizz_handler(int signum, siginfo_t* info, void* p) 
{
	int k = info->si_fd-3;	// Check lib/parse_record.c of https://github.com/deater/perf_event_tests
  disable_trace(perf_fd[k]);
	prev_head=perf_mmap_read(our_mmap[info->si_fd-3],MMAP_DATA_SIZE,prev_head,
         sample_type,read_format,0,NULL,quiet,NULL);

	enable_trace(perf_fd[k]);
	//prev_head = 0;	
  //ioctl(perf_fd[k], PERF_EVENT_IOC_ENABLE, 1);
}

void setupHandler(int sig) {
  // Perf event settings
  struct perf_event_attr pe;

	memset(&pe, 0, sizeof(struct perf_event_attr));
	 
  //pe.type = PERF_TYPE_HW_CACHE;
  pe.type = PERF_TYPE_RAW;
//PERF_TYPE_HW_CACHE;
 // pe.type = PERF_TYPE_RAW;
  pe.size = sizeof(struct perf_event_attr);
	fprintf(stderr, "pe.size is %d\n", pe.size);

	pe.config = 0x1cd;
//(PERF_COUNT_HW_CACHE_L1D << 0) | (PERF_COUNT_HW_CACHE_OP_READ << 8) | (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16);
  pe.sample_period = 4000;
  pe.sample_freq = 4000;
  pe.sample_type = 0xc10f;
  pe.read_format = 1;
//PERF_SAMPLE_IP|PERF_SAMPLE_ADDR;
	 
	//pe.config = (PERF_COUNT_HW_CACHE_L1D << 0) | (PERF_COUNT_HW_CACHE_OP_WRITE << 8) | (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16); 
  pe.disabled = 0;
	pe.pinned=1;
  pe.inherit = 0;
	pe.exclusive = 0;
	pe.exclude_user = 0;
	pe.exclude_kernel = 0;
	pe.exclude_hv = 0;
  pe.exclude_idle = 0;
	pe.mmap = 0;
	pe.comm = 1;
  pe.freq = 1;
  pe.inherit_stat = 0;
  pe.enable_on_exec =1;
  pe.task = 0;
  pe.watermark = 0;
 	pe.precise_ip = 2;
	pe.mmap_data = 0;
	pe.sample_id_all = 1;
	pe.exclude_host = 0;
	pe.exclude_guest = 0;
  pe.exclude_callchain_kernel = 0; /* exclude kernel callchains */
  pe.exclude_callchain_user = 0; /* exclude user callchains */
pe.mmap2 = 1; /* include mmap with inode data     */
 pe.comm_exec = 1; /* flag comm events that are due to an exec */

	pe.wakeup_events = 0;
	pe.wakeup_watermark = 0;
	pe.bp_type = 0;
	pe.bp_addr = 0x3;
  pe.bp_len = 0;
  pe.branch_sample_type = 0;
  pe.sample_regs_user = 0;
  pe.sample_stack_user = 0;
	int k=0; 
  // Create the perf_event for this thread on all CPUs with no event group
	// Second parameter (target thread): 0=self, -1=cpu-wide mode
	// Third parameter cpu: 
	for(k=0; k<32; k++)
{  
	perf_fd[k] = perf_event_open(&pe, getpid(), k, -1, 0);
  	if(perf_fd[k] == -1) {
    fprintf(stderr, "Failed to open perf event file: %s\n", strerror(errno));
    abort();
  }
}
 	for(k=0;k<32;k++)
{
	// Setting up 9 pages to pass information about a trap
	our_mmap[k]=mmap(NULL, 9*4096, PROT_READ|PROT_WRITE, MAP_SHARED, perf_fd[k], 0);
	fprintf(stderr, "perfd %d , mmap addr: %p\n", perf_fd[k], our_mmap[k]);
  // Set the perf_event file to async mode
 	if (fcntl(perf_fd[k], F_SETFL, O_RDONLY|O_NONBLOCK|O_ASYNC) == -1) {
// if(fcntl(perf_fd[k], F_SETFL, O_RDWR|O_NONBLOCK|O_ASYNC) == -1) {
    fprintf(stderr, "Failed to set perf event file to ASYNC mode: %s\n", strerror(errno));
    abort();
 }
}
#if 1
	for(k=0;k<32;k++)
{ 
  // Tell the file to send a SIGUSR1 when an event occurs
  if(fcntl(perf_fd[k], F_SETSIG, sig) == -1) {
    fprintf(stderr, "Failed to set perf event file's async signal: %s\n", strerror(errno));
    abort();
  }
  
  // Deliver the signal to this thread
  if(fcntl(perf_fd[k], F_SETOWN, getpid()) == -1) {
    fprintf(stderr, "Failed to set the owner of the perf event file: %s\n", strerror(errno));
    abort();
  }
#endif
	}
}

size_t get_trace_count(int fd) {
  uint64_t count;
  read(fd, &count, sizeof(uint64_t));
  return count;
}
void *thread_0(void *argv) {
	int i=100000000;
	while(i--) {
		test0=i;
	}
}
void *thread_1(void *argv){
	int i=100000000;
	while(i--) {
		test1=i;
	}
}
	

int main(int argc, char** argv) {
  // Create traces
  setupHandler(SIGIO);
	int iter;
	pthread_t thread[2];
  //struct timeval start, end;
 unsigned long long timediff;
//	pthread_t thread[2];
//	fprintf(stderr, "i address at %p\n", &i); 
//	gettimeofday(&start,NULL);  
// Set a signal handler for SIGUSR1
  struct sigaction sa1 = {
    .sa_sigaction = fizz_handler,
    .sa_flags = SA_SIGINFO
  };

  if(sigaction(SIGIO, &sa1, NULL) == -1) {
    fprintf(stderr, "Failed to set SIGTRAP handler: %s\n", strerror(errno));
    abort();
  }
  
//	fprintf(stderr, "i address at %p before trace\n", &i); 
  // Start traces
 for(iter = 0; iter < 32; iter++) 
  enable_trace(perf_fd[iter]);
  // Shortest fizzbuzz implementation ever:
  //for(i=0; i<0x40000000; i++) { ; }
	pthread_create(&thread[0], NULL, thread_0, NULL);
        fprintf(stderr,"Thread created 0\n");
       pthread_create(&thread[1], NULL, thread_1, NULL);
        fprintf(stderr,"Thread created 1\n");
        pthread_join(thread[0], NULL);
     	pthread_join(thread[1], NULL);
  for(iter = 0; iter < 32; iter++) 
  disable_trace(perf_fd[iter]);
  // Read out the count of events
  //for(iter = 0; iter < 32; iter++)
  //fprintf(stderr, "Perf_fd %d watchpoints tripped %lu times. i is %d\n", iter, get_trace_count(perf_fd[iter]), i);

	munmap(our_mmap, 9*4096);
  return 0;

}
