## Process this file with automake to produce Makefile.in


bin_PROGRAMS =  \
	l2switch

l2switch_SOURCES =  \
	main_l2switch.c

l2switch_LDADD = -L../libreg \
	-L../librule \
	-L../libua \
	-lrule \
	-lua \
	-lreg \
	-lpthread 
