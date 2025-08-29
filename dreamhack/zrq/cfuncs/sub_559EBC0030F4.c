void __fastcall sub_559EBC0030F4(Node *a1)
{
  if ( (__int64)a1->content > 4 )
  {
    a1->content = -1;
  }
  else
  {
    ++a1->content;
    free(&off_559EBC20CCC0);
  }
}