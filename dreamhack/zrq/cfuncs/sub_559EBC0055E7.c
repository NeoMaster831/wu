void __fastcall sub_559EBC0055E7(Node *a1)
{
  signed __int64 v1; // rax

  v1 = sys_munmap(a1->fd->fd->fd->fd->fd->content, a1->fd->content);
  free((void *)a1->content);
}