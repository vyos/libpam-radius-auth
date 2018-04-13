######################################################################
#
#  A minimal 'Makefile', by Alan DeKok <aland@freeradius.org>
#
# $Id: Makefile,v 1.13 2007/03/26 04:22:11 fcusack Exp $
#
#############################################################################
VERSION=1.4.1

######################################################################
#
# If we're really paranoid, use these flags
#CFLAGS = -Wall -Wshadow -Wstrict-prototypes -Wmissing-prototypes -Wnested-externs -Waggregate-return
#
#  If you're not using GCC, then you'll have to change the CFLAGS.
#
# structured this way instead of += so configured CFLAGS can override -Wall
CFLAGS := -Wall -Werror -fPIC ${CFLAGS}

#
# On Irix, use this with MIPSPRo C Compiler, and don't forget to export CC=cc
# gcc on Irix does not work yet for pam_radius
# Also, use gmake instead of make
# Then copy pam_radius_auth.so to /usr/freeware/lib32/security (PAM dir)
# CFLAGS =

#LDSHFLAGS += -shared -Wl,--version-script=pamsymbols.ver
LDSHFLAGS = -shared
LDLIBS += -laudit
BINLIBS += -lcap
LIBLIBS += -lpam

######################################################################
#
#  The default rule to build everything.
#
all: pam_radius_auth.so radius_shell

######################################################################
#
#  Build the object file from the C source.
#
export CFLAGS

src/support.o: src/support.c src/pam_radius_auth.h
	@$(MAKE) -C src $(notdir $@)

src/pam_radius_auth.o: src/pam_radius_auth.c src/pam_radius_auth.h
	@$(MAKE) -C src $(notdir $@)

src/md5.o: src/md5.c src/md5.h
	@$(MAKE) -C src $(notdir $@)

src/radius_shell.o: src/radius_shell.c
	@$(MAKE) -C src $(notdir $@)

#
# This is what should work on Irix:
#pam_radius_auth.so: pam_radius_auth.o md5.o
#	ld -shared pam_radius_auth.o md5.o -L/usr/freeware/lib32 -lpam -lc -o pam_radius_auth.so


######################################################################
#
#  Build the shared library.
#
#  The -Bshareable flag *should* work on *most* operating systems.
#
#  On Solaris, you might try using '-G', instead.
#
#  On systems with a newer GCC, you will need to do:
#
#	gcc -shared pam_radius_auth.o md5.o -lpam -lc -o pam_radius_auth.so
#
pam_radius_auth.so: src/pam_radius_auth.o src/support.o src/md5.o
	$(CC) $(LDFLAGS) $(LDSHFLAGS) $^ $(LDLIBS) $(LIBLIBS) -o $@

radius_shell: src/radius_shell.o
	$(CC) $(LDFLAGS) $^ $(LDLIBS) $(BINLIBS) -o $@

######################################################################
#
#  Check a distribution out of the source tree, and make a tar file.
#
.PHONY: dist
dist:
	git archive --format=tar --prefix=pam_radius-$(VERSION)/ master | gzip > pam_radius-$(VERSION).tar.gz
	gpg --default-key aland@freeradius.org -b pam_radius-$(VERSION).tar.gz


######################################################################
#
#  Clean up everything
#
.PHONY: clean
clean:
	@rm -f *~ *.so *.o src/*.o src/*~ radius_shell
