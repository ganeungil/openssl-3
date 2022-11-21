#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/safestack.h>

typedef struct {
	char *name;
	int age;
} Person;

DEFINE_STACK_OF(Person)  // 스택 Person을 위한 여러 종류의 함수를 생성

Person *PersonMalloc() 
{
	printf ("PersonMalloc() called.()\n");

	Person *a = malloc(sizeof(Person));
	a->name = malloc(20);
	strcpy(a->name, "ex-name");
	a->age = 23;
	return a;
}

void PersonFree(Person *a) 
{
	free(a->name);
	free(a);
}

static int PersonCmp(const Person * const *a,	const Person * const *b) 
{
	int ret;

	printf ("PersonCmp() called.()\n");

	printf("\t1st p: %s, 2nd p: %s \n", (*a)->name, (*b)->name);
	ret = strcmp((*a)->name, (*b)->name);
	return ret;
}

int main() 
{
	int i, num;
	STACK_OF(Person) *stk, *stknew;		// 타입 선언
	Person *s1, *one, *s2;

	stknew = sk_Person_new(PersonCmp);

	s2 = PersonMalloc();		// “PersonMalloc() called.” 출력
	sk_Person_push(stknew, s2);		// stknew: s2

	// “PersonCmp() called.” 출력. find할 때 비교(compare)하여 검색
	i = sk_Person_find(stknew, s2);
	printf("stknew s2 at: %d \n\n", i);		// 0

	// for stk
	// 비교 함수가 null 인것만 제외하면 sk_Person_new() 함수와 동일
	stk = sk_Person_new_null();

	s1 = PersonMalloc();
	sk_Person_push(stk, s1);		// stk: s1

	num = sk_Person_num(stk);	// the # of elements

	for (i=0; i<num; i++) {
		one = sk_Person_value(stk, i);
		printf("student name: %s\n", one->name);
		printf("sutdent age : %d\n", one->age);
	}

	sk_Person_pop_free(stk, PersonFree);
	sk_Person_pop_free(stknew, PersonFree);

	return 0;
}
