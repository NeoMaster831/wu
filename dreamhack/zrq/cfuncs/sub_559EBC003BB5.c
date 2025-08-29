void __fastcall sub_559EBC003BB5(Node *a1)
{
  size_t content; // rbx
  size_t *v2; // r12

  content = a1->content;
  v2 = *(size_t **)content;
  if ( *(_QWORD *)content && (signed __int64)v2[3] < *(_QWORD *)(content + 24) )
  {
    *(_QWORD *)content = *v2;
    *v2 = content;
    **(_QWORD **)(content + 8) = v2;
    if ( *(_QWORD *)content )
      *(_QWORD *)(*(_QWORD *)content + 8LL) = content;
    v2[1] = *(_QWORD *)(content + 8);
    *(_QWORD *)(content + 8) = v2;
    free(a1);
  }
  else
  {
    free((void *)a1->fd->content);
  }
}