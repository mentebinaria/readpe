typedef struct foo_s			/* Foo structure */
{
  float	foo;				/* Real number */
  int	bar;				/* Integer */

  foo_s(float f, int b);
  ~foo_s();

  // 'get_bar()' - Get the value of bar.
  int // O - Value of bar
  get_bar()
  {
    return (bar);
  }

  // 'get_foo()' - Get the value of foo.
  float // O - Value of foo
  get_foo()
  {
    return (foo);
  }

  // 'set_bar()' - Set the value of bar.
  void
  set_bar(int b) // I - Value of bar
  {
    bar = b;
  }

  // 'set_foo()' - Set the value of foo.
  void
  set_foo(float f) // I - Value of foo
  {
    foo = f;
  }
} foo_t;

// 'foo_s::foo_s()' - Create a foo_s structure.
foo_s::foo_s(float f, // I - Value of foo
             int b) // I - Value of bar
{
  foo = f;
  bar = b;
}

// 'foo_s::~foo_s()' - Destroy a foo_s structure.
foo_s::~foo_s()
{
}

typedef struct foo_private_s		/* @private@ */
{
  int	a;				/* Value of "a" */
  char	b[255];				/* Value of "b" */
} foo_private_t;
