/** @file
 *
 * "cz" keyboard mapping
 *
 * This file is automatically generated; do not edit
 *
 */

FILE_LICENCE ( PUBLIC_DOMAIN );

#include <ipxe/keymap.h>

/** "cz" basic remapping */
static struct keymap_key cz_basic[] = {
	{ 0x19, 0x1a },	/* Ctrl-Y => Ctrl-Z */
	{ 0x1a, 0x19 },	/* Ctrl-Z => Ctrl-Y */
	{ 0x1f, 0x1c },	/* 0x1f => 0x1c */
	{ 0x21, 0x31 },	/* '!' => '1' */
	{ 0x22, 0x21 },	/* '"' => '!' */
	{ 0x23, 0x33 },	/* '#' => '3' */
	{ 0x24, 0x34 },	/* '$' => '4' */
	{ 0x25, 0x35 },	/* '%' => '5' */
	{ 0x26, 0x37 },	/* '&' => '7' */
	{ 0x28, 0x39 },	/* '(' => '9' */
	{ 0x29, 0x30 },	/* ')' => '0' */
	{ 0x2a, 0x38 },	/* '*' => '8' */
	{ 0x2b, 0x5e },	/* '+' => '^' */
	{ 0x2d, 0x3d },	/* '-' => '=' */
	{ 0x2f, 0x2d },	/* '/' => '-' */
	{ 0x31, 0x2b },	/* '1' => '+' */
	{ 0x3a, 0x22 },	/* ':' => '"' */
	{ 0x3c, 0x3f },	/* '<' => '?' */
	{ 0x3e, 0x3a },	/* '>' => ':' */
	{ 0x3f, 0x5f },	/* '?' => '_' */
	{ 0x40, 0x32 },	/* '@' => '2' */
	{ 0x59, 0x5a },	/* 'Y' => 'Z' */
	{ 0x5a, 0x59 },	/* 'Z' => 'Y' */
	{ 0x5d, 0x29 },	/* ']' => ')' */
	{ 0x5e, 0x36 },	/* '^' => '6' */
	{ 0x5f, 0x25 },	/* '_' => '%' */
	{ 0x60, 0x3b },	/* '`' => ';' */
	{ 0x79, 0x7a },	/* 'y' => 'z' */
	{ 0x7a, 0x79 },	/* 'z' => 'y' */
	{ 0x7b, 0x2f },	/* '{' => '/' */
	{ 0x7c, 0x27 },	/* '|' => '\'' */
	{ 0x7d, 0x28 },	/* '}' => '(' */
	{ 0x7e, 0x60 },	/* '~' => '`' */
	{ 0, 0 }
};

/** "cz" AltGr remapping */
static struct keymap_key cz_altgr[] = {
	{ 0x21, 0x7e },	/* '!' => '~' */
	{ 0x24, 0x7e },	/* '$' => '~' */
	{ 0x28, 0x7b },	/* '(' => '{' */
	{ 0x29, 0x7e },	/* ')' => '~' */
	{ 0x2c, 0x3c },	/* ',' => '<' */
	{ 0x2e, 0x3e },	/* '.' => '>' */
	{ 0x2f, 0x2a },	/* '/' => '*' */
	{ 0x30, 0x7d },	/* '0' => '}' */
	{ 0x32, 0x40 },	/* '2' => '@' */
	{ 0x33, 0x23 },	/* '3' => '#' */
	{ 0x34, 0x24 },	/* '4' => '$' */
	{ 0x37, 0x26 },	/* '7' => '&' */
	{ 0x38, 0x2a },	/* '8' => '*' */
	{ 0x39, 0x7b },	/* '9' => '{' */
	{ 0x3a, 0x7e },	/* ':' => '~' */
	{ 0x3b, 0x24 },	/* ';' => '$' */
	{ 0x41, 0x7e },	/* 'A' => '~' */
	{ 0x42, 0x7b },	/* 'B' => '{' */
	{ 0x43, 0x26 },	/* 'C' => '&' */
	{ 0x46, 0x5b },	/* 'F' => '[' */
	{ 0x47, 0x5d },	/* 'G' => ']' */
	{ 0x4b, 0x26 },	/* 'K' => '&' */
	{ 0x56, 0x40 },	/* 'V' => '@' */
	{ 0x58, 0x3e },	/* 'X' => '>' */
	{ 0x5a, 0x3c },	/* 'Z' => '<' */
	{ 0x61, 0x7e },	/* 'a' => '~' */
	{ 0x62, 0x7b },	/* 'b' => '{' */
	{ 0x63, 0x26 },	/* 'c' => '&' */
	{ 0x66, 0x5b },	/* 'f' => '[' */
	{ 0x67, 0x5d },	/* 'g' => ']' */
	{ 0x6e, 0x7d },	/* 'n' => '}' */
	{ 0x76, 0x40 },	/* 'v' => '@' */
	{ 0x78, 0x23 },	/* 'x' => '#' */
	{ 0x7b, 0x5b },	/* '{' => '[' */
	{ 0x7d, 0x5d },	/* '}' => ']' */
	{ 0, 0 }
};

/** "cz" keyboard map */
struct keymap cz_keymap __keymap = {
	.name = "cz",
	.basic = cz_basic,
	.altgr = cz_altgr,
};
