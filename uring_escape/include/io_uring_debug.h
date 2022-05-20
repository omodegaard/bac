#include <stdio.h>
#include <inttypes.h>
#include "liburing.h"


#define PRIX64 "llx"


enum {
    STRUCT_URING_SQE,
    STRUCT_URING_CQE,
};

void io_uring_sqe_print(struct io_uring_sqe *_sqe){
    printf("[PRINT] io_uring_sqe\n");
    printf("--->opcode = 0x%" PRIX8 "\n",_sqe->opcode);
    printf("--->flags = 0x%" PRIX8 "\n",_sqe->flags);
    printf("    ioprio = 0x%" PRIX16 "\n",_sqe->ioprio);
    printf("    fd = 0x%" PRIX32 "\n",(__u32)_sqe->fd);
    printf("    -------U-------\n");
    printf("        off = 0x%" PRIX64 "\n",_sqe->off);
    printf("        addr2 = 0x%" PRIX64 "\n",_sqe->addr2);
    printf("    -------U-------\n");
    printf("        addr = 0x%" PRIX64 "\n",_sqe->addr);
    printf("        splice_off_in = 0x%" PRIX64 "\n",_sqe->splice_off_in);
    printf("    len = 0x%" PRIX32 "\n",_sqe->len);
    printf("    -------U-------\n");
    printf("        rw_flags = 0x%" PRIX8 "\n",(__u8)_sqe->rw_flags);
    printf("        fsync_flags = 0x%" PRIX32 "\n",_sqe->fsync_flags);
    printf("        poll_events = 0x%" PRIX16 "\n",_sqe->poll_events);
    printf("        poll32_events = 0x%" PRIX32 "\n",_sqe->poll32_events);
    printf("        sync_range_flags = 0x%" PRIX32 "\n",_sqe->sync_range_flags);
    printf("        msg_flags = 0x%" PRIX32 "\n",_sqe->msg_flags);
    printf("        timeout_flags = 0x%" PRIX32 "\n",_sqe->timeout_flags);
    printf("        accept_flags = 0x%" PRIX32 "\n",_sqe->accept_flags);
    printf("        cancel_flags = 0x%" PRIX32 "\n",_sqe->cancel_flags);
    printf("        open_flags = 0x%" PRIX32 "\n",_sqe->open_flags);
    printf("        statx_flags = 0x%" PRIX32 "\n",_sqe->statx_flags);
    printf("        fadvice_advice = 0x%" PRIX32 "\n",_sqe->fadvise_advice);
    printf("        splice_flags = 0x%" PRIX32 "\n",_sqe->splice_flags);
    printf("        rename_flags = 0x%" PRIX32 "\n",_sqe->rename_flags);
    printf("        unlink_flags = 0x%" PRIX32 "\n",_sqe->unlink_flags);
    //printf("        hardlink_flags = 0x%" PRIX32 "\n",_sqe->hardlink_flags);
    printf("    user_data = 0x%" PRIX64 "\n",_sqe->user_data);
    printf("    -------U-------\n");
    printf("--->    buf_index = 0x%" PRIX16 "\n",_sqe->buf_index);
    printf("--->    buf_group = 0x%" PRIX16 "\n",_sqe->buf_group);
    printf("    personality = 0x%" PRIX16 "\n",_sqe->personality);
    printf("    -------U-------\n");
    printf("        splice_fd_in = 0x%" PRIX32 "\n",_sqe->splice_fd_in);
    //printf("        file_index = 0x%" PRIX32 "\n",_sqe->file_index);
    printf("    __pad2[2] = 0x%" PRIX64 "\n",_sqe->__pad2[2]);
}

void io_uring_cqe_print(struct io_uring_cqe *_cqe){
    printf("[PRINT] io_uring_cqe\n");
    printf("    user_data = 0x%" PRIX64 "\n",_cqe->user_data);
    printf("    res = 0x%" PRIX32 " = %d\n",_cqe->res,_cqe->res);
    printf("    flags = 0x%" PRIX32 "\n",_cqe->flags);
}

int io_uring_print_struct(void *_struct, int type){
    switch(type){
        case STRUCT_URING_SQE :
            io_uring_sqe_print((struct io_uring_sqe *) _struct);
            return 0;
        case STRUCT_URING_CQE :
            io_uring_cqe_print((struct io_uring_cqe *) _struct);
            return 0;
    }
    return 1;
}