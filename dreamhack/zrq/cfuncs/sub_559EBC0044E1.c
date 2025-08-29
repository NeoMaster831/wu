void __fastcall sub_559EBC0044E1(Node *a1)
{
  Node *fd; // r12
  Node *v2; // rbx

  fd = a1->fd->fd->fd->fd;
  v2 = fd->fd->fd->fd->fd->fd->fd->fd->fd->fd;
  v2->content = sys_open((const char *)fd->content, 578, 420);
  if ( (v2->content & 0x8000000000000000LL) != 0LL )
    free((void *)a1->content);
}