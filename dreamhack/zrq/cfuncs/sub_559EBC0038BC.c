void __fastcall sub_559EBC0038BC(Node *a1)
{
  _QWORD *v1; // rax
  Node *fd; // r12

  v1 = malloc(0x30u);
  fd = a1->fd->fd->fd->fd->fd->fd->fd->fd;
  fd->content = v1[2];
  fd->fd->content = v1[2];
  if ( __CFSHR__(sys_munmap((unsigned __int64)(v1 - 2), 0x1000u), 63) )
    free((void *)a1->content);
}