/******************************************************************************
 * Copyright (c) 2004, 2008 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#include <unistd.h>
#include <tftp.h>
#include <ethernet.h>
#include <dhcp.h>
#include <dhcpv6.h>
#include <ipv4.h>
#include <ipv6.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <libbootmsg/libbootmsg.h>
#include <helpers.h>
#include "args.h"
#include "netapps.h"

#define IP_INIT_DEFAULT 5
#define IP_INIT_NONE    0
#define IP_INIT_BOOTP   1
#define IP_INIT_DHCP    2
#define IP_INIT_DHCPV6_STATELESS    3
#define IP_INIT_IPV6_MANUAL         4

#define DEFAULT_BOOT_RETRIES 10
#define DEFAULT_TFTP_RETRIES 20
static int ip_version = 4;

typedef struct {
	char filename[100];
	int  ip_init;
	char siaddr[4];
	ip6_addr_t si6addr;
	char ciaddr[4];
	ip6_addr_t ci6addr;
	char giaddr[4];
	ip6_addr_t gi6addr;
	int  bootp_retries;
	int  tftp_retries;
} obp_tftp_args_t;

/**
 * Print error with preceeding error code
 */
static void netload_error(int errcode, const char *format, ...)
{
	va_list vargs;
	char buf[256];
	int elen;

	elen = sprintf(buf, "E%04X: (net) ", errcode);

	va_start(vargs, format);
	vsnprintf(&buf[elen], sizeof(buf) - elen, format, vargs);
	va_end(vargs);

	bootmsg_error(errcode, &buf[elen - 6]);
	write_mm_log(buf, strlen(buf), 0x91);
}

/**
 * Parses a argument string for IPv6 booting, extracts all
 * parameters and fills a structure accordingly
 *
 * @param  arg_str        string with arguments, separated with ','
 * @param  argc           number of arguments
 * @param  obp_tftp_args  structure which contains the result
 * @return                updated arg_str
 */
static const char * 
parse_ipv6args (const char *arg_str, unsigned int argc,
		obp_tftp_args_t *obp_tftp_args)
{
	char *ptr = NULL;
	char arg_buf[100];

	// find out siaddr
	if (argc == 0)
		memset(&obp_tftp_args->si6addr.addr, 0, 16);
	else {
		argncpy(arg_str, 0, arg_buf, 100);
		if(str_to_ipv6(arg_buf, (uint8_t *) &(obp_tftp_args->si6addr.addr[0]))) {
			arg_str = get_arg_ptr(arg_str, 1);
			--argc;
		}
		else if(arg_buf[0] == 0) {
			memset(&obp_tftp_args->si6addr.addr, 0, 16);
			arg_str = get_arg_ptr(arg_str, 1);
			--argc;
		}
		else
			memset(&obp_tftp_args->si6addr.addr, 0, 16);
	}

	// find out filename
	if (argc == 0)
		obp_tftp_args->filename[0] = 0;
	else {
		argncpy(arg_str, 0, obp_tftp_args->filename, 100);
		for(ptr = obp_tftp_args->filename; *ptr != 0; ++ptr)
			if(*ptr == '\\') {
				*ptr = '/';
			}
		arg_str = get_arg_ptr(arg_str, 1);
		--argc;
	}

	// find out ciaddr
	if (argc == 0)
		memset(&obp_tftp_args->ci6addr, 0, 16);
	else {
		argncpy(arg_str, 0, arg_buf, 100);
		if (str_to_ipv6(arg_buf, (uint8_t *) &(obp_tftp_args->ci6addr.addr[0]))) {
			arg_str = get_arg_ptr(arg_str, 1);
			--argc;
		}
		else if(arg_buf[0] == 0) {
			memset(&obp_tftp_args->ci6addr.addr, 0, 16);
			arg_str = get_arg_ptr(arg_str, 1);
			--argc;
		}
		else
			memset(&obp_tftp_args->ci6addr.addr, 0, 16);
	}

	// find out giaddr
	if (argc == 0)
		memset(&obp_tftp_args->gi6addr, 0, 16);
	else {
		argncpy(arg_str, 0, arg_buf, 100);
		if (str_to_ipv6(arg_buf, (uint8_t *) &(obp_tftp_args->gi6addr.addr)) ) {
			arg_str = get_arg_ptr(arg_str, 1);
			--argc;
		}
		else if(arg_buf[0] == 0) {
			memset(&obp_tftp_args->gi6addr, 0, 16);
			arg_str = get_arg_ptr(arg_str, 1);
			--argc;
		}
		else
			memset(&obp_tftp_args->gi6addr.addr, 0, 16);
	}

	return arg_str;
}


/**
 * Parses a argument string for IPv4 booting, extracts all
 * parameters and fills a structure accordingly
 *
 * @param  arg_str        string with arguments, separated with ','
 * @param  argc           number of arguments
 * @param  obp_tftp_args  structure which contains the result
 * @return                updated arg_str
 */
static const char * 
parse_ipv4args (const char *arg_str, unsigned int argc,
		obp_tftp_args_t *obp_tftp_args)
{
	char *ptr = NULL;
	char arg_buf[100];

	// find out siaddr
	if(argc==0) {
		memset(obp_tftp_args->siaddr, 0, 4);
	} else {
		argncpy(arg_str, 0, arg_buf, 100);
		if(strtoip(arg_buf, obp_tftp_args->siaddr)) {
			arg_str = get_arg_ptr(arg_str, 1);
			--argc;
		}
		else if(arg_buf[0] == 0) {
			memset(obp_tftp_args->siaddr, 0, 4);
			arg_str = get_arg_ptr(arg_str, 1);
			--argc;
		}
		else
			memset(obp_tftp_args->siaddr, 0, 4);
	}

	// find out filename
	if(argc==0)
		obp_tftp_args->filename[0] = 0;
	else {
		argncpy(arg_str, 0, obp_tftp_args->filename, 100);
		for(ptr = obp_tftp_args->filename; *ptr != 0; ++ptr)
			if(*ptr == '\\')
				*ptr = '/';
		arg_str = get_arg_ptr(arg_str, 1);
		--argc;
	}

	// find out ciaddr
	if(argc==0)
		memset(obp_tftp_args->ciaddr, 0, 4);
	else {
		argncpy(arg_str, 0, arg_buf, 100);
		if(strtoip(arg_buf, obp_tftp_args->ciaddr)) {
			arg_str = get_arg_ptr(arg_str, 1);
			--argc;
		}
		else if(arg_buf[0] == 0) {
			memset(obp_tftp_args->ciaddr, 0, 4);
			arg_str = get_arg_ptr(arg_str, 1);
			--argc;
		}
		else
			memset(obp_tftp_args->ciaddr, 0, 4);
	}

	// find out giaddr
	if(argc==0)
		memset(obp_tftp_args->giaddr, 0, 4);
	else {
		argncpy(arg_str, 0, arg_buf, 100);
		if(strtoip(arg_buf, obp_tftp_args->giaddr)) {
			arg_str = get_arg_ptr(arg_str, 1);
			--argc;
		}
		else if(arg_buf[0] == 0) {
			memset(obp_tftp_args->giaddr, 0, 4);
			arg_str = get_arg_ptr(arg_str, 1);
			--argc;
		}
		else
			memset(obp_tftp_args->giaddr, 0, 4);
	}

	return arg_str;
}

/**
 * Parses a argument string which is given by netload, extracts all
 * parameters and fills a structure according to this
 *
 * Netload-Parameters:
 *    [bootp,]siaddr,filename,ciaddr,giaddr,bootp-retries,tftp-retries
 *
 * @param  arg_str        string with arguments, separated with ','
 * @param  obp_tftp_args  structure which contains the result
 * @return                none
 */
static void
parse_args(const char *arg_str, obp_tftp_args_t *obp_tftp_args)
{
	unsigned int argc;
	char arg_buf[100];

	memset(obp_tftp_args, 0, sizeof(*obp_tftp_args));

	argc = get_args_count(arg_str);

	// find out if we should use BOOTP or DHCP
	if(argc==0)
		obp_tftp_args->ip_init = IP_INIT_DEFAULT;
	else {
		argncpy(arg_str, 0, arg_buf, 100);
		if (strcasecmp(arg_buf, "bootp") == 0) {
			obp_tftp_args->ip_init = IP_INIT_BOOTP;
			arg_str = get_arg_ptr(arg_str, 1);
			--argc;
		}
		else if(strcasecmp(arg_buf, "dhcp") == 0) {
			obp_tftp_args->ip_init = IP_INIT_DHCP;
			arg_str = get_arg_ptr(arg_str, 1);
			--argc;
		}
		else if(strcasecmp(arg_buf, "ipv6") == 0) {
			obp_tftp_args->ip_init = IP_INIT_DHCPV6_STATELESS;
			arg_str = get_arg_ptr(arg_str, 1);
			--argc;
			ip_version = 6;
		}
		else
			obp_tftp_args->ip_init = IP_INIT_DEFAULT;
	}

	if (ip_version == 4) {
		arg_str = parse_ipv4args (arg_str, argc, obp_tftp_args);
	}
	else if (ip_version == 6) {
		arg_str = parse_ipv6args (arg_str, argc, obp_tftp_args);
	}

	// find out bootp-retries
	if (argc == 0)
		obp_tftp_args->bootp_retries = DEFAULT_BOOT_RETRIES;
	else {
		argncpy(arg_str, 0, arg_buf, 100);
		if(arg_buf[0] == 0)
			obp_tftp_args->bootp_retries = DEFAULT_BOOT_RETRIES;
		else {
			obp_tftp_args->bootp_retries = strtol(arg_buf, 0, 10);
			if(obp_tftp_args->bootp_retries < 0)
				obp_tftp_args->bootp_retries = DEFAULT_BOOT_RETRIES;
		}
		arg_str = get_arg_ptr(arg_str, 1);
		--argc;
	}

	// find out tftp-retries
	if (argc == 0)
		obp_tftp_args->tftp_retries = DEFAULT_TFTP_RETRIES;
	else {
		argncpy(arg_str, 0, arg_buf, 100);
		if(arg_buf[0] == 0)
			obp_tftp_args->tftp_retries = DEFAULT_TFTP_RETRIES;
		else {
			obp_tftp_args->tftp_retries = strtol(arg_buf, 0, 10);
			if(obp_tftp_args->tftp_retries < 0)
				obp_tftp_args->tftp_retries = DEFAULT_TFTP_RETRIES;
		}
		arg_str = get_arg_ptr(arg_str, 1);
		--argc;
	}
}

/**
 * DHCP: Wrapper for obtaining IP and configuration info from DHCP server
 *       for both IPv4 and IPv6.
 *       (makes several attempts).
 *
 * @param  ret_buffer    buffer for returning BOOTP-REPLY packet data
 * @param  fn_ip         contains the following configuration information:
 *                       client MAC, client IP, TFTP-server MAC,
 *                       TFTP-server IP, Boot file name
 * @param  retries       No. of DHCP attempts
 * @param  flags         flags for specifying type of dhcp attempt (IPv4/IPv6)
 *                       ZERO   - attempt DHCPv4 followed by DHCPv6
 *                       F_IPV4 - attempt only DHCPv4
 *                       F_IPV6 - attempt only DHCPv6
 * @return               ZERO - IP and configuration info obtained;
 *                       NON ZERO - error condition occurs.
 */
int dhcp(char *ret_buffer, struct filename_ip *fn_ip, unsigned int retries,
	 int flags)
{
	int i = (int) retries+1;
	int rc = -1;

	printf("  Requesting information via DHCP%s:     ",
	       flags == F_IPV4 ? "v4" : flags == F_IPV6 ? "v6" : "");

	if (flags != F_IPV6)
		dhcpv4_generate_transaction_id();
	if (flags != F_IPV4)
		dhcpv6_generate_transaction_id();

	do {
		printf("\b\b\b%03d", i-1);
		if (getchar() == 27) {
			printf("\nAborted\n");
			return -1;
		}
		if (!--i) {
			printf("\nGiving up after %d DHCP requests\n", retries);
			return -1;
		}
		if (!flags || (flags == F_IPV4)) {
			ip_version = 4;
			rc = dhcpv4(ret_buffer, fn_ip);
		}
		if ((!flags && (rc == -1)) || (flags == F_IPV6)) {
			ip_version = 6;
			set_ipv6_address(fn_ip->fd, 0);
			rc = dhcpv6(ret_buffer, fn_ip);
			if (rc == 0) {
				memcpy(&fn_ip->own_ip6, get_ipv6_address(), 16);
				break;
			}

		}
		if (rc != -1) /* either success or non-dhcp failure */
			break;
	} while (1);
	printf("\b\b\b\bdone\n");

	return rc;
}

/**
 * Seed the random number generator with our mac and current timestamp
 */
static void seed_rng(uint8_t mac[])
{
	unsigned int seed;

	asm volatile("mftbl %0" : "=r"(seed));
	seed ^= (mac[2] << 24) | (mac[3] << 16) | (mac[4] << 8) | mac[5];
	srand(seed);
}

static int tftp_load(filename_ip_t *fnip, unsigned char *buffer, int len,
		     unsigned int retries, int32_t mode,
		     int32_t blksize, int ip_vers)
{
	tftp_err_t tftp_err;
	int rc;

	rc = tftp(fnip, buffer, len, retries, &tftp_err, mode, blksize, ip_vers);

	if (rc > 0) {
		printf("  TFTP: Received %s (%d KBytes)\n", fnip->filename,
		       rc / 1024);
	} else if (rc == -1) {
		netload_error(0x3003, "unknown TFTP error");
		return -103;
	} else if (rc == -2) {
		netload_error(0x3004, "TFTP buffer of %d bytes "
			"is too small for %s",
			len, fnip->filename);
		return -104;
	} else if (rc == -3) {
		netload_error(0x3009, "file not found: %s",
			fnip->filename);
		return -108;
	} else if (rc == -4) {
		netload_error(0x3010, "TFTP access violation");
		return -109;
	} else if (rc == -5) {
		netload_error(0x3011, "illegal TFTP operation");
		return -110;
	} else if (rc == -6) {
		netload_error(0x3012, "unknown TFTP transfer ID");
		return -111;
	} else if (rc == -7) {
		netload_error(0x3013, "no such TFTP user");
		return -112;
	} else if (rc == -8) {
		netload_error(0x3017, "TFTP blocksize negotiation failed");
		return -116;
	} else if (rc == -9) {
		netload_error(0x3018, "file exceeds maximum TFTP transfer size");
		return -117;
	} else if (rc <= -10 && rc >= -15) {
		const char *icmp_err_str;
		switch (rc) {
		case -ICMP_NET_UNREACHABLE - 10:
			icmp_err_str = "net unreachable";
			break;
		case -ICMP_HOST_UNREACHABLE - 10:
			icmp_err_str = "host unreachable";
			break;
		case -ICMP_PROTOCOL_UNREACHABLE - 10:
			icmp_err_str = "protocol unreachable";
			break;
		case -ICMP_PORT_UNREACHABLE - 10:
			icmp_err_str = "port unreachable";
			break;
		case -ICMP_FRAGMENTATION_NEEDED - 10:
			icmp_err_str = "fragmentation needed and DF set";
			break;
		case -ICMP_SOURCE_ROUTE_FAILED - 10:
			icmp_err_str = "source route failed";
			break;
		default:
			icmp_err_str = " UNKNOWN";
			break;
		}
		netload_error(0x3005, "ICMP ERROR \"%s\"", icmp_err_str);
		return -105;
	} else if (rc == -40) {
		netload_error(0x3014, "TFTP error occurred after "
			"%d bad packets received",
			tftp_err.bad_tftp_packets);
		return -113;
	} else if (rc == -41) {
		netload_error(0x3015, "TFTP error occurred after "
			"missing %d responses",
			tftp_err.no_packets);
		return -114;
	} else if (rc == -42) {
		netload_error(0x3016, "TFTP error missing block %d, "
			"expected block was %d",
			tftp_err.blocks_missed,
			tftp_err.blocks_received);
		return -115;
	}

	return rc;
}

int netload(char *buffer, int len, char *ret_buffer, int huge_load,
	    int block_size, char *args_fs, int alen)
{
	int rc;
	filename_ip_t fn_ip;
	int fd_device;
	obp_tftp_args_t obp_tftp_args;
	char null_ip[4] = { 0x00, 0x00, 0x00, 0x00 };
	char null_ip6[16] = { 0x00, 0x00, 0x00, 0x00,
			     0x00, 0x00, 0x00, 0x00,
			     0x00, 0x00, 0x00, 0x00, 
			     0x00, 0x00, 0x00, 0x00 };
	uint8_t own_mac[6];

	puts("\n Initializing NIC");
	memset(&fn_ip, 0, sizeof(filename_ip_t));

	/***********************************************************
	 *
	 * Initialize network stuff and retrieve boot informations
	 *
	 ***********************************************************/

	/* Wait for link up and get mac_addr from device */
	for(rc=0; rc<DEFAULT_BOOT_RETRIES; ++rc) {
		if(rc > 0) {
			set_timer(TICKS_SEC);
			while (get_timer() > 0);
		}
		fd_device = socket(0, 0, 0, (char*) own_mac);
		if(fd_device != -2)
			break;
		if(getchar() == 27) {
			fd_device = -2;
			break;
		}
	}

	if (fd_device == -1) {
		netload_error(0x3000, "Could not read MAC address");
		return -100;
	}
	else if (fd_device == -2) {
		netload_error(0x3006, "Could not initialize network device");
		return -101;
	}

	fn_ip.fd = fd_device;

	printf("  Reading MAC address from device: "
	       "%02x:%02x:%02x:%02x:%02x:%02x\n",
	       own_mac[0], own_mac[1], own_mac[2],
	       own_mac[3], own_mac[4], own_mac[5]);

	// init ethernet layer
	set_mac_address(own_mac);

	seed_rng(own_mac);

	if (alen > 0) {
		char args[256];
		if (alen > sizeof(args) - 1) {
			puts("ERROR: Parameter string is too long.");
			return -7;
		}
		/* Convert forth string into NUL-terminated C-string */
		strncpy(args, args_fs, alen);
		args[alen] = 0;
		parse_args(args, &obp_tftp_args);
		if(obp_tftp_args.bootp_retries - rc < DEFAULT_BOOT_RETRIES)
			obp_tftp_args.bootp_retries = DEFAULT_BOOT_RETRIES;
		else
			obp_tftp_args.bootp_retries -= rc;
	}
	else {
		memset(&obp_tftp_args, 0, sizeof(obp_tftp_args_t));
		obp_tftp_args.ip_init = IP_INIT_DEFAULT;
		obp_tftp_args.bootp_retries = DEFAULT_BOOT_RETRIES;
		obp_tftp_args.tftp_retries = DEFAULT_TFTP_RETRIES;
	}
	memcpy(&fn_ip.own_ip, obp_tftp_args.ciaddr, 4);

	//  reset of error code
	rc = 0;

	/* if we still have got all necessary parameters, then we don't
	   need to perform an BOOTP/DHCP-Request */
	if (ip_version == 4) {
		if (memcmp(obp_tftp_args.ciaddr, null_ip, 4) != 0
		    && memcmp(obp_tftp_args.siaddr, null_ip, 4) != 0
		    && obp_tftp_args.filename[0] != 0) {

			memcpy(&fn_ip.server_ip, &obp_tftp_args.siaddr, 4);
			obp_tftp_args.ip_init = IP_INIT_NONE;
		}
	}
	else if (ip_version == 6) {
		if (memcmp(&obp_tftp_args.si6addr, null_ip6, 16) != 0
		    && obp_tftp_args.filename[0] != 0) {
			memcpy(&fn_ip.server_ip6.addr[0],
			       &obp_tftp_args.si6addr.addr, 16);
			obp_tftp_args.ip_init = IP_INIT_IPV6_MANUAL;
		}
		else {
			obp_tftp_args.ip_init = IP_INIT_DHCPV6_STATELESS;
		}
	}

	// construction of fn_ip from parameter
	switch(obp_tftp_args.ip_init) {
	case IP_INIT_BOOTP:
		// if giaddr in not specified, then we have to identify
		// the BOOTP server via broadcasts
		if(memcmp(obp_tftp_args.giaddr, null_ip, 4) == 0) {
			// don't do this, when using DHCP !!!
			fn_ip.server_ip = 0xFFFFFFFF;
		}
		// if giaddr is specified, then we have to use this
		// IP address as proxy to identify the BOOTP server
		else {
			memcpy(&fn_ip.server_ip, obp_tftp_args.giaddr, 4);
		}
		rc = bootp(ret_buffer, &fn_ip, obp_tftp_args.bootp_retries);
		break;
	case IP_INIT_DHCP:
		rc = dhcp(ret_buffer, &fn_ip, obp_tftp_args.bootp_retries, F_IPV4);
		break;
	case IP_INIT_DHCPV6_STATELESS:
		rc = dhcp(ret_buffer, &fn_ip,
			  obp_tftp_args.bootp_retries, F_IPV6);
		break;
	case IP_INIT_IPV6_MANUAL:
		if (memcmp(&obp_tftp_args.ci6addr, null_ip6, 16)) {
			set_ipv6_address(fn_ip.fd, &obp_tftp_args.ci6addr);
		} else {
			/*
			 * If no client address has been specified, then
			 * use a link-local or stateless autoconfig address
			 */
			set_ipv6_address(fn_ip.fd, NULL);
			memcpy(&fn_ip.own_ip6, get_ipv6_address(), 16);
		}
		break;
	case IP_INIT_DEFAULT:
		rc = dhcp(ret_buffer, &fn_ip, obp_tftp_args.bootp_retries, 0);
		break;
	case IP_INIT_NONE:
	default:
		break;
	}

	if(rc >= 0 && ip_version == 4) {
		if(memcmp(obp_tftp_args.ciaddr, null_ip, 4) != 0
		&& memcmp(obp_tftp_args.ciaddr, &fn_ip.own_ip, 4) != 0)
			memcpy(&fn_ip.own_ip, obp_tftp_args.ciaddr, 4);

		if(memcmp(obp_tftp_args.siaddr, null_ip, 4) != 0
		&& memcmp(obp_tftp_args.siaddr, &fn_ip.server_ip, 4) != 0)
			memcpy(&fn_ip.server_ip, obp_tftp_args.siaddr, 4);

		// init IPv4 layer
		set_ipv4_address(fn_ip.own_ip);
	}
	else if (rc >= 0 && ip_version == 6) {
		if(memcmp(&obp_tftp_args.ci6addr.addr, null_ip6, 16) != 0
		&& memcmp(&obp_tftp_args.ci6addr.addr, &fn_ip.own_ip6, 16) != 0)
			memcpy(&fn_ip.own_ip6, &obp_tftp_args.ci6addr.addr, 16);

		if(memcmp(&obp_tftp_args.si6addr.addr, null_ip6, 16) != 0
		&& memcmp(&obp_tftp_args.si6addr.addr, &fn_ip.server_ip6.addr, 16) != 0)
			memcpy(&fn_ip.server_ip6.addr, &obp_tftp_args.si6addr.addr, 16);
	}
	if (rc == -1) {
		netload_error(0x3001, "Could not get IP address");
		close(fn_ip.fd);
		return -101;
	}

	if (ip_version == 4) {
		printf("  Using IPv4 address: %d.%d.%d.%d\n",
			((fn_ip.own_ip >> 24) & 0xFF), ((fn_ip.own_ip >> 16) & 0xFF),
			((fn_ip.own_ip >>  8) & 0xFF), ( fn_ip.own_ip        & 0xFF));
	} else if (ip_version == 6) {
		char ip6_str[40];
		ipv6_to_str(fn_ip.own_ip6.addr, ip6_str);
		printf("  Using IPv6 address: %s\n", ip6_str);
	}

	if (rc == -2) {
		netload_error(0x3002, "ARP request to TFTP server "
			"(%d.%d.%d.%d) failed",
			((fn_ip.server_ip >> 24) & 0xFF),
			((fn_ip.server_ip >> 16) & 0xFF),
			((fn_ip.server_ip >>  8) & 0xFF),
			( fn_ip.server_ip        & 0xFF));
		close(fn_ip.fd);
		return -102;
	}
	if (rc == -4 || rc == -3) {
		netload_error(0x3008, "Can't obtain TFTP server IP address");
		close(fn_ip.fd);
		return -107;
	}

	/***********************************************************
	 *
	 * Load file via TFTP into buffer provided by OpenFirmware
	 *
	 ***********************************************************/

	if (obp_tftp_args.filename[0] != 0) {
		strncpy((char *) fn_ip.filename, obp_tftp_args.filename, sizeof(fn_ip.filename)-1);
		fn_ip.filename[sizeof(fn_ip.filename)-1] = 0;
	}

	if (ip_version == 4) {
		printf("  Requesting file \"%s\" via TFTP from %d.%d.%d.%d\n",
			fn_ip.filename,
			((fn_ip.server_ip >> 24) & 0xFF),
			((fn_ip.server_ip >> 16) & 0xFF),
			((fn_ip.server_ip >>  8) & 0xFF),
			( fn_ip.server_ip        & 0xFF));
	} else if (ip_version == 6) {
		char ip6_str[40];
		printf("  Requesting file \"%s\" via TFTP from ", fn_ip.filename);
		ipv6_to_str(fn_ip.server_ip6.addr, ip6_str);
		printf("%s\n", ip6_str);
	}

	/* Do the TFTP load and print error message if necessary */
	rc = tftp_load(&fn_ip, (unsigned char *)buffer, len,
		       obp_tftp_args.tftp_retries, huge_load,
		       block_size, ip_version);

	if (obp_tftp_args.ip_init == IP_INIT_DHCP)
		dhcp_send_release(fn_ip.fd);

	close(fn_ip.fd);

	return rc;
}
