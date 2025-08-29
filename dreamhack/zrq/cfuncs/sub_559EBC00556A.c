void __fastcall sub_559EBC00556A(Node *a1)
{
  a1->fd->fd->fd->fd->fd->fd->content = (size_t)malloc(0x30u) - 16;
  if ( (*(_QWORD *)(a1->fd->fd->fd->fd->fd->fd->content - 8) & 0xFFFFFFFFFFFFFFF0LL) != 0x120 )
    free((void *)a1->content);
}