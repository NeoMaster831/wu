void __fastcall sub_559EBC004171(Node *a1)
{
  Node *fd; // rbx
  size_t content; // r12

  fd = a1->fd->fd;
  content = fd->fd->fd->content;
  if ( content > a1->content )
  {
    *(_QWORD *)(content + fd->content + 8 * a1->content) = a1->content + fd->content;
    ++a1->content;
    free(a1);
  }
}