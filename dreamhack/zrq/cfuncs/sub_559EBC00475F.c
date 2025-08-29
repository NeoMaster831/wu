void __fastcall sub_559EBC00475F(Node *a1)
{
  Node *fd; // rbx
  unsigned __int64 v2; // rax

  fd = a1->fd->fd->fd->fd->fd->fd;
  _BitScanReverse64(&v2, fd->fd->fd->content);
  LOBYTE(fd->fd->fd->content) = 64 - (v2 ^ 0x3F);
  *(_BYTE *)fd->fd->fd->fd->content++ = fd->fd->fd->content;
  a1->fd->fd->content = (size_t)&unk_559EBC208020 + 48 * (unsigned __int8)fd->fd->fd->content + 16;
  a1->fd->fd->fd->content = (size_t)&off_559EBC20BB50;
  LOBYTE(fd->content) = fd->fd->fd->content - 8;
}