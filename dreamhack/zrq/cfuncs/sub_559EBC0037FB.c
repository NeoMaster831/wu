void __fastcall sub_559EBC0037FB(Node *a1)
{
  size_t content; // r12
  _QWORD *v2; // rbx

  content = a1->content;
  v2 = (_QWORD *)a1->fd->content;
  if ( !v2[3] )
  {
    if ( *(_QWORD *)content )
      *(_QWORD *)(*(_QWORD *)content + 8LL) = v2;
    *v2 = *(_QWORD *)content;
    v2[1] = content;
    *(_QWORD *)content = v2;
  }
  ++v2[3];
}