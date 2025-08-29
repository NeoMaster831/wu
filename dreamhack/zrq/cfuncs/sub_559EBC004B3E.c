void __fastcall sub_559EBC004B3E(Node *a1)
{
  Node *fd; // rbx

  fd = a1->fd->fd;
  sys_write(fd->fd->fd->fd->content, (const char *)(fd->content + a1->content), 1u);
  a1->content += 21LL;
  if ( (signed __int64)a1->content < (signed __int64)fd->fd->fd->content )
    free(a1);
}