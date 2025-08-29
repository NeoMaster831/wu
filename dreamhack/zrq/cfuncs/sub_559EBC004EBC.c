void __fastcall sub_559EBC004EBC(Node *a1)
{
  size_t content; // rbx

  content = a1->content;
  *(_QWORD *)a1->fd->content = content;
  a1->fd->fd->content = content;
  free(&off_559EBC20BD30);
}