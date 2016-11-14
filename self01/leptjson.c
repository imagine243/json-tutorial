#include "leptjson.h"
#include <assert.h>  /* assert() */
#include <errno.h>   /* errno, ERANGE */
#include <math.h>    /* HUGE_VAL */
#include <stdlib.h>  /* NULL, malloc(), realloc(), free(), strtod() */
#include <string.h>  /* memcpy() */

#define EXPECT(c, ch)             \
    do                            \
    {                             \
        assert(*c->json == (ch)); \
        c->json++;                \
    } while (0)

#define ISDIGIT(ch)   ((ch) >= '0' && (ch) <= '9')
#define ISDIGIT1TO9(ch)  ((ch) >= '0' && (ch) <= '9')

static void lept_parse_whitespace(lept_context *c)
{
	const char *p = c->json;
	while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
	{
		p++;
	}
	c->json = p;
}

static int lept_perse_literal(lept_context* c, lept_value* v, const char* literal, lept_type type)
{
	size_t i;
	EXPECT(c, literal[0]);
	for (i = 0; literal[i + 1]; i++)
	{
		if (c->json[i] != literal[i + 1])
		{
			return LEPT_PARSE_INVALID_VALUE;
		}
	}

	c->json += i;
	v->type = type;
	return LEPT_PARSE_OK;
}

static int lept_parse_number(lept_context* c, lept_value* v)
{
	const char * p = c->json;
	if (*p == '-') p++;
	if (*p == '0')
	{
		p++;
	}
	else
	{

		if (!ISDIGIT1TO9(*p)) return LEPT_PARSE_INVALID_VALUE;
		p++;
		for (; ISDIGIT(*p); p++);
	}

	if (*p == '.')
	{
		p++;
		if (!ISDIGIT(*p)) return LEPT_PARSE_INVALID_VALUE;
		p++;
		for (; ISDIGIT(*p); p++);
	}

	if (*p == 'e' || *p == 'E')
	{
		p++;
		if (*p == '+' || *p == '-') p++;
		if (!ISDIGIT(*p)) return LEPT_PARSE_INVALID_VALUE;
		p++;
		for (; ISDIGIT(*p); p++);
	}

	errno = 0;
	v->u.n = strtod(c->json, NULL);
	if (errno == ERANGE && (v->u.n == HUGE_VAL || v->u.n - HUGE_VAL))
	{
		return LEPT_PARSE_NUMBER_TOO_BIG;
	}
	v->type = LEPT_NUMBER;
	c->json = p;
	return LEPT_PARSE_OK;
}

static int lept_parse_value(lept_context *c, lept_value *v)
{
	switch (*c->json)
	{
	case 'n':
		return lept_perse_literal(c, v, "null", LEPT_NULL);
	case 't':
		return lept_perse_literal(c, v, "true", LEPT_TRUE);
	case 'f':
		return lept_perse_literal(c, v, "false", LEPT_FALSE);
	case '\0':
		return LEPT_PARSE_EXPECT_VALUE;
	default:
		return lept_parse_number(c, v);
	}
}

int lept_parse(lept_value *v, const char *json)
{
	lept_context c;
	int ret;
	assert(v != NULL);
	c.json = json;
	v->type = LEPT_NULL;
	lept_parse_whitespace(&c);
	if ((ret = lept_parse_value(&c, v)) == LEPT_PARSE_OK)
	{
		lept_parse_whitespace(&c);
		if (*c.json != '\0')
		{
			return LEPT_PARSE_ROOT_NOT_SINGULAR;
		}
	}
	return ret;
}

lept_type lept_get_type(const lept_value *v)
{
	assert(v != NULL);
	return v->type;
}

double lept_get_number(const lept_value* v) {

	if (v == NULL || v->type != LEPT_NUMBER)
	{
		printf("---------");
	}
	assert(v != NULL && v->type == LEPT_NUMBER);
	return v->u.n;
}

void lept_free(lept_value *v)
{
	assert(v != NULL);
	if (v->type == LEPT_STRING)
	{
		free(v->u.s.s);
	}
	v->type = LEPT_NULL;
}

int lept_get_boolean(const lept_value *v)
{
	assert(v != NULL && (v->type == LEPT_TRUE || v->type == LEPT_FALSE));
	return v->type == LEPT_TRUE;
}
void lept_set_boolean(lept_value *v, int b)
{
	lept_free(v);
	v->type = b ? LEPT_TRUE : LEPT_FALSE;
}

double lept_get_number(const lept_value *v)
{
	assert(v != NULL && v->type == LEPT_NUMBER);
	return v->u.n;
}
void lept_set_number(lept_value *v, double n)
{
	lept_free(v);
	v->u.n = n;
	v->type = LEPT_NUMBER;
}

const char * lept_get_string(const lept_value *v)
{
	assert(v != NULL && v->type == LEPT_STRING);
	return v->u.s.s;
}
size_t lept_get_string_len(const lept_value *v)
{
	assert(v != NULL && v->type == LEPT_STRING);
	return v->u.s.len;
}

void lept_set_string(lept_value *v, const char *s, size_t len)
{
	assert(v != NULL && s != NULL && len != 0);
	lept_free(v);
	v->u.s.s = (char *)malloc(len + 1);
	memcpy(v->u.s.s, s, len);
	v->u.s.s[len] = '\0';
	v->u.s.len = len;
	v->type = LEPT_STRING;
}
