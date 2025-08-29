void __fastcall sub_559EBC004919(Node *a1)
{
  _QWORD *content; // r12
  _QWORD *v2; // rbx

  content = (_QWORD *)a1->fd->fd->content;
  v2 = (_QWORD *)a1->content;
  v2[3] = a1->fd->content;
  *v2 = &off_559EBC20C390;
  if ( v2 != (_QWORD *)*content )
  {
    a1->content = v2[1];
    free(&off_559EBC20C0C0);
  }
}