/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

#define MY_MAP_REUSEPORT_SIZE 	10
#define MY_MAP_STATS_SIZE 		3
#define MY_MAP_TOTAL_SIZE 		(MY_MAP_REUSEPORT_SIZE + MY_MAP_STATS_SIZE)

#define MY_MAP_STATS_SUCCESS_FIRST	(MY_MAP_REUSEPORT_SIZE + 0)
#define MY_MAP_STATS_SUCCESS_SECOND	(MY_MAP_REUSEPORT_SIZE + 1)
#define MY_MAP_STATS_FAILURE	(MY_MAP_REUSEPORT_SIZE + 2)

#endif /* __COMMON_KERN_USER_H */
