/// Find nested lock+irqsave functions that use the same flags variables
///
// Confidence: High
// Copyright: (C) 2010-2012 Nicolas Palix.  GPLv2.
// Copyright: (C) 2010-2012 Julia Lawall, INRIA/LIP6.  GPLv2.
// Copyright: (C) 2010-2012 Gilles Muller, INRIA/LiP6.  GPLv2.
// URL: http://coccinelle.lip6.fr/
// Comments:
// Options: --no-includes --include-headers

virtual context
virtual org
virtual report

@pre exists@
expression lock1,flags;
position p1;
@@

(
spin_lock_irqsave@p1(lock1,flags)
|
read_lock_irqsave@p1(lock1,flags)
|
write_lock_irqsave@p1(lock1,flags)
)

@r exists@
expression lock2 != pre.lock1;
expression f <= pre.flags;
expression pre.lock1,pre.flags;
position pre.p1,p2;
@@

(
*spin_lock_irqsave@p1(lock1,flags)
|
*read_lock_irqsave@p1(lock1,flags)
|
*write_lock_irqsave@p1(lock1,flags)
)
... when != f
(
*spin_lock_irqsave@p2(lock2,flags)
|
*read_lock_irqsave@p2(lock2,flags)
|
*write_lock_irqsave@p2(lock2,flags)
)

// ----------------------------------------------------------------------

@script:python depends on org@
p1 << pre.p1;
p2 << r.p2;
@@

cocci.print_main("original lock",p1)
cocci.print_secs("nested lock+irqsave that reuses flags",p2)

@script:python depends on report@
p1 << pre.p1;
p2 << r.p2;
@@

msg="ERROR: nested lock+irqsave that reuses flags from line %s." % (p1[0].line)
coccilib.report.print_report(p2[0], msg)
