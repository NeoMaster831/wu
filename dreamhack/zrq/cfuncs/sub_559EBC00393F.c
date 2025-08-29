void __fastcall sub_559EBC00393F(Node *a1)
{
  Node *fd; // rbx

  fd = a1->fd->fd->fd->fd->fd->fd->fd;
  *(_BYTE *)fd->fd->fd->content++ = fd->content;
  a1->fd->fd->content = (size_t)&unk_559EBC208020 + 48 * (unsigned __int8)fd->content + 16;
}