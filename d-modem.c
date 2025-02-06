/* 
 * Copyright (C) 2021 Aon plc
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA 
 */

#include <unistd.h>
#include <stdbool.h>
#include <time.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>

#include <pjsua-lib/pjsua.h>

#include "slmodemd/modem.h"

#define SIGNATURE PJMEDIA_SIG_CLASS_PORT_AUD('D','M')

struct dmodem {
	pjmedia_port base;
	pj_timestamp timestamp;
	pj_sock_t sock;
};

static struct dmodem port;
static bool destroying = false;
static pj_pool_t *pool;

static int volume = 0;
static pjsua_conf_port_id left_audio_id, right_audio_id;

static void error_exit(const char *title, pj_status_t status) {
	pjsua_perror(__FILE__, title, status);
	if (!destroying) {
		destroying = true;
		pjsua_destroy();
		exit(1);
	}
}

static pj_status_t dmodem_put_frame(pjmedia_port *this_port, pjmedia_frame *frame) {
	struct dmodem *sm = (struct dmodem *)this_port;
	int len;

	if (frame->type == PJMEDIA_FRAME_TYPE_AUDIO) {
		if ((len=write(sm->sock, frame->buf, frame->size)) != frame->size) {
			error_exit("error writing frame",0);
		}
	}

	return PJ_SUCCESS;
}

static pj_status_t dmodem_get_frame(pjmedia_port *this_port, pjmedia_frame *frame) {
	struct dmodem *sm = (struct dmodem *)this_port;
	struct modem_socket_frame modem_frame = { 0 };

	frame->size = PJMEDIA_PIA_MAX_FSZ(&this_port->info);
	if (frame->size != SIP_FRAMESIZE * 2) {
		fprintf(stderr,"incompatible frame size: %lu, expected: %d!\n", frame->size, SIP_FRAMESIZE * 2);
		exit(EXIT_FAILURE);
	}

	int len;
	if ((len=read(sm->sock, &modem_frame, sizeof(modem_frame))) != sizeof(modem_frame)) {
		error_exit("error reading frame",0);
	}

	len = frame->size;
	memcpy(frame->buf, modem_frame.buf, len);
	if (modem_frame.volume != volume) {
		float level = 0.0;
		switch (modem_frame.volume) {
			case 0:
				level = 0.0;
				break;
			case 1:
				level = 1.0/3.0;
				break;
			case 2:
				level = 2.0/3.0;
				break;
			case 3:
			default:
				level = 1.0;
				break;
		}
		printf("Volume: %d -> %f\n", modem_frame.volume, level);
		pjsua_conf_adjust_tx_level(left_audio_id, level);
		pjsua_conf_adjust_tx_level(right_audio_id, level);
		volume = modem_frame.volume;
	}

	frame->timestamp.u64 = sm->timestamp.u64;
	frame->type = PJMEDIA_FRAME_TYPE_AUDIO;
	sm->timestamp.u64 += PJMEDIA_PIA_PTIME(&this_port->info);

	return PJ_SUCCESS;
}

static pj_status_t dmodem_on_destroy(pjmedia_port *this_port) {
	printf("destroy\n");
	exit(-1);
}

/* Callback called by the library when call's state has changed */
static void on_call_state(pjsua_call_id call_id, pjsip_event *e) {
	pjsua_call_info ci;

	PJ_UNUSED_ARG(e);

	pjsua_call_get_info(call_id, &ci);
	PJ_LOG(3,(__FILE__, "Call %d state=%.*s", call_id,
				(int)ci.state_text.slen,
				ci.state_text.ptr));

	if (ci.state == PJSIP_INV_STATE_DISCONNECTED) {
		close(port.sock);
		if (!destroying) {
			destroying = true;
			pjsua_destroy();
			exit(0);
		}
	}
}

/* Callback called by the library when call's media state has changed */
static void on_call_media_state(pjsua_call_id call_id) {
	pjmedia_snd_port *audiodev;
	pjmedia_port *sc, *left, *right;
	pjsua_call_info ci;
	pjsua_conf_port_id port_id;
	static int done=0;

	pjsua_call_get_info(call_id, &ci);

//	printf("media_status %d media_cnt %d ci.conf_slot %d aud.conf_slot %d\n",ci.media_status,ci.media_cnt,ci.conf_slot,ci.media[0].stream.aud.conf_slot);
	if (ci.media_status == PJSUA_CALL_MEDIA_ACTIVE) {
		if (!done) {
			if (pjsua_conf_add_port(pool, &port.base, &port_id) != PJ_SUCCESS)
				error_exit("can't add modem port",0);
			if (pjsua_conf_connect(ci.conf_slot, port_id) != PJ_SUCCESS)
				error_exit("can't connect modem port (out)",0);
			if (pjsua_conf_connect(port_id, ci.conf_slot) != PJ_SUCCESS)
				error_exit("can't connect modem port (in)",0);

			//pjsua_conf_adjust_rx_level(port_id, 1.0);
			//pjsua_conf_adjust_rx_level(ci.conf_slot, 1.0);

			if (pjmedia_splitcomb_create(pool, SIP_RATE, 2, SIP_FRAMESIZE, 16, 0, &sc) != PJ_SUCCESS)
				error_exit("can't create splitter/combiner",0);

			// left
			if (pjmedia_splitcomb_create_rev_channel(pool, sc, 0, 0, &left) != PJ_SUCCESS)
				error_exit("can't create left channel",0);
			if (pjsua_conf_add_port(pool, left, &left_audio_id) != PJ_SUCCESS)
				error_exit("can't add left port",0);
			if (pjsua_conf_connect(ci.conf_slot, left_audio_id) != PJ_SUCCESS)
				error_exit("can't connect left port",0);
			pjsua_conf_adjust_tx_level(left_audio_id, 0.0);

			// right
			if (pjmedia_splitcomb_create_rev_channel(pool, sc, 1, 0, &right) != PJ_SUCCESS)
				error_exit("can't create right channel",0);
			if (pjsua_conf_add_port(pool, right, &right_audio_id) != PJ_SUCCESS)
				error_exit("can't add right port",0);
			if (pjsua_conf_connect(port_id, right_audio_id) != PJ_SUCCESS)
				error_exit("can't connect right port",0);
			pjsua_conf_adjust_tx_level(right_audio_id, 0.0);

			if (pjmedia_snd_port_create(pool, -1, -1, SIP_RATE, 2, SIP_FRAMESIZE, 16, 0, &audiodev) != PJ_SUCCESS)
				error_exit("can't create audio device port",0);
			if (pjmedia_snd_port_connect(audiodev, sc) != PJ_SUCCESS)
				error_exit("can't connect audio device port",0);

			//Kick off audio
			printf("Kicking off audio!\n");
			char buf[SIP_FRAMESIZE*2];
			memset(buf,0,sizeof(buf));
			write(port.sock, buf, sizeof(buf));

			done = 1;
		}
	}
}

static void sig_handler(int sig, siginfo_t *si, void *x) {
	switch(sig) {
		case SIGTERM:
			pjsua_call_hangup_all();
			exit(EXIT_SUCCESS);
			break;
		default:
			break;
	}
}


int main(int argc, char *argv[]) {
	pjsua_acc_id acc_id;
	pj_status_t status;

	if (argc != 3) {
		return -1;
	}

	signal(SIGPIPE,SIG_IGN);

	char *dialstr = argv[1];

	char *sip_user = getenv("SIP_LOGIN");
	if (!sip_user) {
		return -1;
	}
	char *sip_domain = strchr(sip_user,'@');
	if (!sip_domain) {
		return -1;
	}
	*sip_domain++ = '\0';
	char *sip_pass = strchr(sip_user,':');
	if (!sip_pass) {
		return -1;
	}
	*sip_pass++ = '\0';

	status = pjsua_create();
	if (status != PJ_SUCCESS) error_exit("Error in pjsua_create()", status);

	/* Init pjsua */
	{
		pjsua_config cfg;
		pjsua_logging_config log_cfg;
		pjsua_media_config med_cfg;

		pjsua_config_default(&cfg);
		cfg.cb.on_call_media_state = &on_call_media_state;
		cfg.cb.on_call_state = &on_call_state;

		pjsua_logging_config_default(&log_cfg);
		log_cfg.console_level = 4;

		pjsua_media_config_default(&med_cfg);
		med_cfg.clock_rate = SIP_RATE;
		med_cfg.quality = 10;
		med_cfg.no_vad = true;
		med_cfg.ec_tail_len = 0;
#if 0
		med_cfg.jb_max = 2000;
//		med_cfg.jb_init = 200;
#endif
		med_cfg.audio_frame_ptime = 20;
		med_cfg.has_ioqueue = true;
		med_cfg.thread_cnt = 1;

		status = pjsua_init(&cfg, &log_cfg, &med_cfg);
		if (status != PJ_SUCCESS) error_exit("Error in pjsua_init()", status);
	}

	pjsua_set_ec(0,0); // maybe?
	//pjsua_set_null_snd_dev();
	
	/* g711 only */
	pjsua_codec_info codecs[32];
	unsigned count = sizeof(codecs)/sizeof(*codecs);
	pjsua_enum_codecs(codecs,&count);
	for (int i=0; i<count; i++) {
		int pri = 0;
		if (pj_strcmp2(&codecs[i].codec_id,"PCMU/8000/1") == 0) {
			pri = 1;
		} else if (pj_strcmp2(&codecs[i].codec_id,"PCMA/8000/1") == 0) {
			pri = 1;
		}
		pjsua_codec_set_priority(&codecs[i].codec_id, pri);
//		printf("codec: %s %d\n",pj_strbuf(&codecs[i].codec_id),pri);
	}

	/* Add UDP transport. */
	{
		pjsua_transport_config cfg;

		pjsua_transport_config_default(&cfg);
		cfg.port = 0;
		status = pjsua_transport_create(PJSIP_TRANSPORT_UDP, &cfg, NULL);
		if (status != PJ_SUCCESS) error_exit("Error creating transport", status);
	}

	pj_caching_pool cp;
	pj_caching_pool_init(&cp, NULL, 1024*1024);
	pool = pj_pool_create(&cp.factory, "pool1", 4000, 4000, NULL);

	pj_str_t name = pj_str("dmodem");
	
	memset(&port,0,sizeof(port));
	port.sock = atoi(argv[2]); // inherited from parent
	pjmedia_port_info_init(&port.base.info, &name, SIGNATURE, SIP_RATE, 1, 16, SIP_FRAMESIZE);
	port.base.put_frame = dmodem_put_frame;
	port.base.get_frame = dmodem_get_frame;
	port.base.on_destroy = dmodem_on_destroy;


	char buf[1024] = { 0 };
	/* Initialization is done, now start pjsua */
	status = pjsua_start();
	if (status != PJ_SUCCESS) error_exit("Error starting pjsua", status);

	{
		pjsua_acc_config cfg;
		pjsua_acc_config_default(&cfg);
		snprintf(buf,sizeof(buf),"sip:%s@%s",sip_user,sip_domain);
		pj_strdup2(pool,&cfg.id,buf);
		snprintf(buf,sizeof(buf),"sip:%s",sip_domain);
		pj_strdup2(pool,&cfg.reg_uri,buf);
		cfg.register_on_acc_add = false;
		cfg.cred_count = 1;
		cfg.cred_info[0].realm = pj_str("*");
		cfg.cred_info[0].scheme = pj_str("digest");
		cfg.cred_info[0].username = pj_str(sip_user);
		cfg.cred_info[0].data_type = PJSIP_CRED_DATA_PLAIN_PASSWD;
		cfg.cred_info[0].data = pj_str(sip_pass);

		status = pjsua_acc_add(&cfg, PJ_TRUE, &acc_id);
		if (status != PJ_SUCCESS) error_exit("Error adding account", status);
	}

	char *dial = dialstr;
	//handle atdt and atdp
	if (dial[0] == 't' || dial[0] == 'T' ||
	    dial[0] == 'p' || dial[0] == 'P') {
		dial++;
	}

	snprintf(buf,sizeof(buf),"sip:%s@%s",dial,sip_domain);
	printf("calling %s\n",buf);
	pj_str_t uri = pj_str(buf);

	struct sigaction sa = { 0 };
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = sig_handler;
	sigaction(SIGTERM, &sa, NULL);

	printf("Dialer PID: %d\n", getpid());

	pjsua_call_id callid;
	status = pjsua_call_make_call(acc_id, &uri, 0, NULL, NULL, &callid);
	if (status != PJ_SUCCESS) error_exit("Error making call", status);

	struct timespec ts = {100, 0};
	while(1) {
		nanosleep(&ts,NULL);
	}

	return 0;
}
