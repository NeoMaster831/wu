void __fastcall sub_559EBC00363B(Node *a1)
{
  Node *fd; // rbx
  signed __int64 v2; // rax

  fd = a1->fd->fd->fd;
  if ( (signed __int64)(fd->content + a1->content) % 15 )
  {
    v2 = sys_write(fd->fd->fd->fd->fd->fd->fd->content, (const char *)&a1->content + 1, 1u);
    ++fd->content;
    free(a1);
  }
}