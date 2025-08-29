void __fastcall sub_559EBC004998(Node *a1)
{
  _QWORD *content; // rbx

  content = (_QWORD *)a1->content;
  content[1] = 65;
  content[9] = 65;
  content[17] = 65;
  content[2] = 0;
  free(content + 2);
  free((void *)a1->fd->content);
}