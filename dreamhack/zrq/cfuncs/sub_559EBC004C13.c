void __fastcall sub_559EBC004C13(Node *a1)
{
  if ( (__int64)a1->content > 13 )
  {
    a1->content = -1;
  }
  else
  {
    ++a1->content;
    free(&off_559EBC20C3C0);
  }
}