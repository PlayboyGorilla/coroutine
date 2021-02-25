#ifndef __LIB_ERRNO_H
#define __LIB_ERRNO_H

#define ERR_OK 0
/*all error codes are < 0*/
/*memory & misc*/
#define ERR_NOMEM		(-1) /*most common mistake when coding*/
#define ERR_TIMEOUT		(-2) /*I/O timeout*/
#define ERR_STATE		(-3) /*FSM error -- unexpected stuff based on the current state*/
#define ERR_NOTPERMIT		(-4)
#define ERR_DATA_NOTENOUGH	(-5)
#define ERR_OVERFLOW		(-6)
#define ERR_SIGNATURE		(-7) /*signature verification failed*/
#define ERR_UNNECESSARY		(-8)
#define ERR_INVAL		(-9)
#define ERR_INPROGRESS		(-10) /*either an operation is in progress or it's not completely finished*/
#define ERR_BUSY		(-11)
#define ERR_AGAIN		(-12)
#define ERR_CREATE_THREAD	(-13) /*failed to create a new thread*/
#define ERR_NOT_HANDLED		(-14)
#define ERR_AUTH_FAIL		(-15)
#define ERR_ABORTED		(-16)
#define ERR_NOT_FOUND		(-17) /*some kind of item can not be found in registration*/
#define ERR_FORMAT		(-18) /*file format error*/
#define ERR_IO			(-19) /*some sort of IO operation failed*/
#define ERR_EXISTED		(-20)	/* some resource already existed */
#define ERR_NOTSUPPORTED	(-21)	/* operation not supported */
#define ERR_ROUTE		(-22)	/* routing problems */
#define ERR_RESET		(-23)	/* something is reset */
#define ERR_CONN		(-24)	/* connection */
#define ERR_CLOSED		(-25)	/* resource closed already */
#define ERR_UNKNOWN		(-99)
/*socket*/
#define ERR_SOCKET_BEGIN (-100)
#define ERR_SOCKET_CONNRESET (ERR_SOCKET_BEGIN - 1)
#define ERR_SOCKET_FAIL (ERR_SOCKET_BEGIN - 100)
#define ERR_SOCKET_END (ERR_SOCKET_BEGIN - 200)
/*packet*/
#define ERR_PACKET_BEGIN ERR_SOCKET_END
#define ERR_PACKET_MAC (ERR_PACKET_BEGIN - 1) /*mac not right*/
#define ERR_PACKET_FORMAT (ERR_PACKET_BEGIN -2) /*packet format inconsistent*/
#define ERR_PACKET_2LARGE (ERR_PACKET_BEGIN - 3) /*packet length exceeds tolerance*/
#define ERR_PACKET_TYPE (ERR_PACKET_BEGIN - 4) /*unexpected packet type*/

#endif
