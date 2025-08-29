void __fastcall sub_559EBC0028F9(Node *a1)
{
  Node *fd; // rbx
  Node *v2; // r12
  _BYTE *content; // r13

  fd = a1->fd->fd->fd->fd->fd;
  v2 = fd->fd->fd->fd->fd;
  content = (_BYTE *)v2->content;
  if ( (char)fd->fd->content <= 0 )
  {
    free(&off_559EBC20CC60);
  }
  else
  {
    *content = *(__int64 *)(fd->content + 32) >> fd->fd->content;
    a1->fd->fd->content = (size_t)&unk_559EBC208020 + 48 * (unsigned __int8)*content + 16;
    a1->fd->fd->fd->content = (size_t)&off_559EBC20C090;
    a1->fd->fd->fd->fd->content = (size_t)a1;
    ++v2->content;
  }
}