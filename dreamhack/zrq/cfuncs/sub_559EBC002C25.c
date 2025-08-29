void __fastcall sub_559EBC002C25(Node *a1)
{
  char *content; // rsi
  __int64 v2; // rax

  content = (char *)a1->content;
  v2 = sys_read(0, content, 0x2000LL - (_QWORD)content + a1->fd->fd->fd->content);
  if ( v2 < 0 )
    free(&off_559EBC20C840);
  else
    content[v2 - 1] = 0;
}