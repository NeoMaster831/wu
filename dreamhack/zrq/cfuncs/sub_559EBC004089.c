void __fastcall sub_559EBC004089(Node *a1)
{
  signed __int64 v1; // rax

  a1->fd->content *= 2LL;
  if ( (++a1->fd->content & 0x100) != 0 )
  {
    v1 = sys_write(a1->fd->fd->fd->content, (const char *)&a1->fd->content, 1u);
    a1->fd->content = 1;
  }
  free((void *)a1->content);
}