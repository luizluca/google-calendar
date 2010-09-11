/** Google Calendar plugin
 *
 * Copyright (c) 2006 Eduardo Pereira Habkost <ehabkost@raisama.net>
 * Copyright (c) 2008 Adenilson Cavalcanti da Silva <adenilson.silva@indt.org.br>
 * Copyright (c) 2010 Chris Frey <cdfrey@foursquare.net> for NetDirect Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Lesser Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301  USA
 *
 */

/* TODO:
 * - review code for leaks
 *
 */

#include <opensync/opensync.h>
#include <opensync/opensync-plugin.h>
#include <opensync/opensync-helper.h>
#include <opensync/opensync-capabilities.h>
#include <opensync/opensync-format.h>
#include <opensync/opensync-xmlformat.h>
#include <opensync/opensync-data.h>
#include <opensync/opensync-version.h>

#include <glib.h>

#include <libxml/tree.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>
#include <gcal_status.h>
#include <gcalendar.h>
#include <gcontact.h>
#include "xslt_aux.h"

#include "timestamp.h"
#include <time.h>
#include <sys/time.h>

static void gc_connect(OSyncObjTypeSink *sink, OSyncPluginInfo *info,
			OSyncContext *ctx, void *data);
static void gc_get_changes_calendar(OSyncObjTypeSink *sink,
			OSyncPluginInfo *info, OSyncContext *ctx,
			osync_bool slow_sync, void *data);
static void gc_get_changes_contact(OSyncObjTypeSink *sink,
			OSyncPluginInfo *info, OSyncContext *ctx,
			osync_bool slow_sync, void *data);
static void gc_commit_change_calendar(OSyncObjTypeSink *sink,
				OSyncPluginInfo *info, OSyncContext *ctx,
				OSyncChange *change, void *data);
static void gc_commit_change_contact(OSyncObjTypeSink *sink,
				OSyncPluginInfo *info, OSyncContext *ctx,
				OSyncChange *change, void *data);
static void gc_sync_done(OSyncObjTypeSink *sink, OSyncPluginInfo *info,
			OSyncContext *ctx, void *data);

static int timestamp_cmp(const char *timestamp1, const char *timestamp2)
{
	// timestamp (RFC3339) formating string
	char format[] = "%FT%T";
	struct tm first, second;
	time_t t_first, t_second;
	int result = 0;

	if (!timestamp1 && !timestamp2)
		return 0;
	if (!timestamp2)
		return 1;
	if (!timestamp1)
		return -1;

	// From timestamp string to time structure
	timestamp2tm(timestamp1, format, &first);
	timestamp2tm(timestamp2, format, &second);

	//
	// From time structure to calendar time (since
	// Epoch (00:00:00 UTC, January 1, 1970)
	//
	t_first = mktime(&first);
	t_second = mktime(&second);

	if (t_first == t_second)
		result = 0;
	else if (t_first > t_second)
		result = 1;
	else if (t_first < t_second)
		result = -1;

	return result;

}

const char* findstr(const char *data, const char *format)
{
	const char *match = format;
	const char *start = data;

	while( *data && *match ) {
		int matched = 0;

		switch( *match )
		{
		case '9':
			matched = isdigit(*data);
			break;
		default:
			matched = (*data == *match);
			break;
		}

		if( matched ) {
			data++;
			match++;
			if( *match == 0 )
				return start;
		}
		else {
			data++;
			start = data;
			match = format;
		}
	}

	return data;
}

// vtime2gtime
//
// Searches through data, converting every vtime string it finds into
// a timestamp compatible with Google.  i.e. it converts time in the
// format: YYYYMMDDTHHMMSSZ to YYYY-MM-DDTHH:MM:SSZ
//
// Caller is responsible for freeing the returned string.
//
char* vtime2gtime(const char *data)
{
	char *ret = malloc(strlen(data) * 2);
	char *target = ret;

	while( *data ) {
		// search for YYYYMMDDTHHMMSS
		const char *match = findstr(data, "99999999T999999");

		// copy the non-matching data
		memcpy(target, data, match - data);
		target += match - data;

		// was there a match?
		if( *match ) {
			// adjust the timestamp
			target[0] = match[0];
			target[1] = match[1];
			target[2] = match[2];
			target[3] = match[3];
			target[4] = '-';
			target[5] = match[4];
			target[6] = match[5];
			target[7] = '-';
			target[8] = match[6];
			target[9] = match[7];
			target[10] = match[8];
			target[11] = match[9];
			target[12] = match[10];
			target[13] = ':';
			target[14] = match[11];
			target[15] = match[12];
			target[16] = ':';
			target[17] = match[13];
			target[18] = match[14];
			target += 19;
			data = match + 15;
		}
		else {
			data = match;
		}
	}
	*target = 0;
	return ret;
}

struct gc_plgdata;

struct gc_gdata
{
	// parent
	struct gc_plgdata *plgdata;

	// xslt filenames
	const char *google2osync_file;
	const char *osync2google_file;

	// sync marker
	const char *timestamp_name;
	char *timestamp;

	// sync handle
	gcal_t handle;

	// sink/format
	OSyncObjFormat *format;

	// XSLT context resource struct
	struct xslt_resources *xslt_google2osync;
	struct xslt_resources *xslt_osync2google;
};

struct gc_plgdata
{
	char *url;
	char *username;
	char *password;
	char *timezone;
	char *xslt_path;
	// libgcal resources
	struct gc_gdata cal;
	struct gc_gdata cont;
};

static void free_gdata(struct gc_gdata *gdata)
{
	if( gdata->timestamp )
		free(gdata->timestamp);
	if( gdata->handle )
		gcal_delete(gdata->handle);
	if( gdata->format)
		osync_objformat_unref(gdata->format);
	if( gdata->xslt_google2osync )
		xslt_delete(gdata->xslt_google2osync);
	if( gdata->xslt_osync2google )
		xslt_delete(gdata->xslt_osync2google);
}

static void free_plg(struct gc_plgdata *plgdata)
{
	free_gdata(&plgdata->cal);
	free_gdata(&plgdata->cont);

	if (plgdata->xslt_path)
		free(plgdata->xslt_path);
	if (plgdata->timezone)
		free(plgdata->timezone);
	if (plgdata->url)
		xmlFree(plgdata->url);
	if (plgdata->username)
		xmlFree(plgdata->username);
	if (plgdata->password)
		xmlFree(plgdata->password);
	g_free(plgdata);
}

static void gc_connect(OSyncObjTypeSink *sink, OSyncPluginInfo *info,
			OSyncContext *ctx, void *data)
{
	osync_trace(TRACE_ENTRY, "%s(%p, %p, %p)", __func__, data, info, ctx);
	int result;
	struct gc_gdata *gdata = data;
	OSyncError *error = NULL;
	char buffer[512];
	strcpy(buffer, "");

	result = gcal_get_authentication(gdata->handle,
					 gdata->plgdata->username,
					 gdata->plgdata->password);
	if (result == -1)
		goto error;

	// google -> osync
	snprintf(buffer, sizeof(buffer) - 1, "%s%s",
		 gdata->plgdata->xslt_path,
		 gdata->google2osync_file);
	if ((result = xslt_initialize(gdata->xslt_google2osync, buffer)))
		goto error;
	osync_trace(TRACE_INTERNAL, "loaded xslt: %s", buffer);

	// osync -> google
	snprintf(buffer, sizeof(buffer) - 1, "%s%s",
		 gdata->plgdata->xslt_path,
		 gdata->osync2google_file);
	if ((result = xslt_initialize(gdata->xslt_osync2google, buffer)))
		goto error;
	osync_trace(TRACE_INTERNAL, "loaded xslt: %s", buffer);

	osync_context_report_success(ctx);
	osync_trace(TRACE_EXIT, "%s", __func__);
	return;

error:
	osync_trace(TRACE_INTERNAL, "Failed to load stylesheet: '%s'", buffer);
	osync_error_set(&error, OSYNC_ERROR_GENERIC,
		"Unable load stylesheet data: '%s'", buffer);
	osync_context_report_osyncerror(ctx, error);
}

static void gc_get_changes_calendar(OSyncObjTypeSink *sink,
			OSyncPluginInfo *info, OSyncContext *ctx,
			osync_bool slow_sync, void *data)
{
	osync_trace(TRACE_ENTRY, "%s(%p, %p, %p)", __func__, data, info, ctx);
	struct gc_gdata *gdata = data;
	OSyncError *error = NULL;
	OSyncData *odata = NULL;
	OSyncChange *chg = NULL;
	int result = 0, i;
	char *timestamp = NULL, *msg = NULL;
	const char *raw_xml = NULL;
	char *seen = NULL;
	OSyncError *state_db_error = NULL;
	OSyncSinkStateDB *state_db = NULL;
	gcal_event_t event;
	struct gcal_event_array all_events;

	state_db = osync_objtype_sink_get_state_db(sink);
	if( !state_db )
		goto error;

	timestamp = osync_sink_state_get(state_db, gdata->timestamp_name,
						&state_db_error);
	if (!timestamp) {
		msg = "gcalendar: Anchor returned is NULL!";
		goto error;
	}

	osync_trace(TRACE_INTERNAL, "timestamp is: '%s'\n", timestamp);

	if (slow_sync || strlen(timestamp) == 0) {
		osync_trace(TRACE_INTERNAL, "\n\t\tgcal: slow sync, or first time\n");
		result = gcal_get_events(gdata->handle, &all_events);

	} else {
		result = gcal_get_updated_events(gdata->handle, &all_events,
						 timestamp);
	}

	if (result) {
		msg = "Failed getting events!";
		goto error;
	}

	osync_trace(TRACE_INTERNAL, "gcalendar: got them all!\n");
	if (all_events.length == 0) {
		osync_trace(TRACE_INTERNAL, "gcalendar: no changes...\n");
		goto exit;
	} else {
		osync_trace(TRACE_INTERNAL, "gcalendar: changes count: %d\n",
			    all_events.length);
	}

	// Calendar returns most recently updated event as first element
	for (i = 0; i < all_events.length; ++i) {
		// cleanup for a fresh run
		if (seen) {
			osync_free(seen);
			seen = NULL;
		}

		// grab the next event object
		event = gcal_event_element(&all_events, i);
		if (!event) {
			osync_trace(TRACE_INTERNAL, "Cannot access updated event %d", i);
			goto error;
		}

		// save first timestamp as new "done" mark
		if (i == 0) {
			if (gdata->timestamp)
				free(gdata->timestamp);
			gdata->timestamp = strdup(gcal_event_get_updated(event));
			if (!gdata->timestamp) {
				msg = "Failed copying event timestamp!\n";
				goto error;
			}
		}

		// are we done yet?  libgcal includes the entry with the
		// given timestamp, so if the timestamp of this event
		// is <= to the timestamp we asked for, then we're done
		if( !slow_sync && timestamp_cmp(gcal_event_get_updated(event), timestamp) <= 0 )
			break;

		osync_trace(TRACE_INTERNAL, "gevent: timestamp:%s\tevent:%s\n",
			    timestamp, gcal_event_get_updated(event));

		// grab ID for current change... this is a Google URL
		// the edit_url and etag are required later for modification,
		// so save them in the state_db as the "seen" marker
		const char *url = gcal_event_get_url(event);
		const char *etag = gcal_event_get_etag(event);

		// check state_db for id to see if we've seen this
		// one before
		seen = osync_sink_state_get(state_db, url, &state_db_error);

		// determine changetype - we do not use osync_hashtable here
		// because I believe that requires us to download all
		// events in order to feed the timestamp to the hashtable
		// function... hashtable is more suited to a local access,
		// instead of internet access.
		OSyncChangeType ct = OSYNC_CHANGE_TYPE_UNKNOWN;
		if( gcal_event_is_deleted(event) ) {
			ct = OSYNC_CHANGE_TYPE_DELETED;

			// remember this item as deleted
			if( !osync_sink_state_set(state_db, url, "", &state_db_error) ) {
				msg = "Error setting state_db with url";
				goto error;
			}
			if( slow_sync || !seen || strlen(seen) == 0 ) {
				// in slow sync mode, we don't care about
				// deleted objects
				continue;
			}
		}
		else {
			if( !slow_sync && seen && strlen(seen) > 0 ) {
				// we've seen this object before
				ct = OSYNC_CHANGE_TYPE_MODIFIED;
			}
			else {
				ct = OSYNC_CHANGE_TYPE_ADDED;
			}

			// the etag will have changed for MODIFIED, and
			// it's a new item if ADDED, so save the url/etag 
			// string either way
			// FIXME - should perhaps set this only after
			// success, such as in the done() plugin call
			if( !osync_sink_state_set(state_db, url, etag, &state_db_error) ) {
				msg = "Error setting state_db with url/etag";
				goto error;
			}
		}

		// create change object
		chg = osync_change_new(&error);
		if( !chg )
			goto cleanup;

		// setup the change
		osync_change_set_uid(chg, url);
		osync_change_set_hash(chg, gcal_event_get_updated(event));
		osync_change_set_changetype(chg, ct);

		// fill in the data
		if( ct != OSYNC_CHANGE_TYPE_DELETED ) {
			raw_xml = gcal_event_get_xml(event);
			if( xslt_transform(gdata->xslt_google2osync, raw_xml) ) {
				osync_change_unref(chg);
				goto error;
			}

			raw_xml = (char*) gdata->xslt_google2osync->xml_str;
			odata = osync_data_new(strdup(raw_xml),
					       strlen(raw_xml),
					       gdata->format, &error);
			if( !odata ) {
				osync_change_unref(chg);
				goto cleanup;
			}
		}
		else {
			// deleted changes need empty data sets
			odata = osync_data_new(NULL, 0, gdata->format, &error);
			if( !odata ) {
				osync_change_unref(chg);
				goto cleanup;
			}
		}

		osync_data_set_objtype(odata,
				osync_objtype_sink_get_name(sink));
		osync_change_set_data(chg, odata);
		osync_data_unref(odata);

		osync_context_report_change(ctx, chg);
		osync_change_unref(chg);
	}


exit:
	osync_context_report_success(ctx);
	goto cleanup;

error:
	osync_context_report_error(ctx, OSYNC_ERROR_GENERIC, "%s", msg);

cleanup:
	osync_error_unref(&error);
	gcal_cleanup_events(&all_events);

	// osync_sink_state_get uses osync_strdup
	osync_free(timestamp);

	if (seen)
		osync_free(seen);
}


static void gc_get_changes_contact(OSyncObjTypeSink *sink,
			OSyncPluginInfo *info, OSyncContext *ctx,
			osync_bool slow_sync, void *data)
{
	osync_trace(TRACE_ENTRY, "%s(%p, %p, %p)", __func__, data, info, ctx);
	struct gc_gdata *gdata = data;
	OSyncError *error = NULL;
	OSyncData *odata = NULL;
	OSyncChange *chg = NULL;
	int result = 0, i;
	char *timestamp = NULL, *msg = NULL;
	const char *raw_xml = NULL;
	char *seen = NULL;
	OSyncError *state_db_error = NULL;
	OSyncSinkStateDB *state_db = NULL;
	gcal_contact_t contact;
	struct gcal_contact_array all_contacts;

	state_db = osync_objtype_sink_get_state_db(sink);
	if( !state_db )
		goto error;

	timestamp = osync_sink_state_get(state_db, gdata->timestamp_name,
					  &state_db_error);
	if (!timestamp) {
		msg = "gcontact: Anchor returned is NULL!";
		goto error;
	}

	osync_trace(TRACE_INTERNAL, "timestamp is: '%s'\n", timestamp);

	if (slow_sync || strlen(timestamp) == 0) {
		osync_trace(TRACE_INTERNAL, "\n\t\tgcont: slow sync, or first time\n");
		result = gcal_get_contacts(gdata->handle, &all_contacts);

	} else {
		gcal_deleted(gdata->handle, SHOW);
		result = gcal_get_updated_contacts(gdata->handle, &all_contacts,
						   timestamp);
	}

	if (result) {
		msg = "Failed getting contacts!";
		goto error;
	}

	osync_trace(TRACE_INTERNAL, "gcontact: got them all!\n");
	if (all_contacts.length == 0) {
		osync_trace(TRACE_INTERNAL, "gcontact: no changes...\n");
		goto exit;
	} else
		osync_trace(TRACE_INTERNAL, "gcontact: changes count: %d\n",
			    all_contacts.length);

	// Contacts returns most recently updated entry as last element
	for (i = 0; i < all_contacts.length; ++i) {
		// cleanup for a fresh run
		if (seen) {
			osync_free(seen);
			seen = NULL;
		}

		// grab the next event object
		contact = gcal_contact_element(&all_contacts, i);
		if (!contact) {
			osync_trace(TRACE_INTERNAL, "Cannot access updated contact %d", i);
			goto error;
		}

		// save first timestamp as new "done" mark
		if (i == 0) {
			if (gdata->timestamp)
				free(gdata->timestamp);
			gdata->timestamp = strdup(gcal_contact_get_updated(contact));
			if (!gdata->timestamp) {
				msg = "Failed copying contact timestamp!\n";
				goto error;
			}
		}

		// are we done yet?  libgcal includes the entry with the
		// given timestamp, so if the timestamp of this contact
		// is <= to the timestamp we asked for, then we're done
		if( !slow_sync && timestamp_cmp(gcal_contact_get_updated(contact), timestamp) <= 0 )
			break;

		osync_trace(TRACE_INTERNAL, "gcontact: timestamp:%s\tcontact:%s\n",
			    timestamp, gcal_contact_get_updated(contact));

		// grab ID for current change... this is a Google URL
		// the edit_url and etag are required later for modification,
		// so save them in the state_db as the "seen" marker
		const char *url = gcal_contact_get_url(contact);
		const char *etag = gcal_contact_get_etag(contact);

		// check state_db for id to see if we've seen this
		// one before
		seen = osync_sink_state_get(state_db, url, &state_db_error);

		// determine changetype - we do not use osync_hashtable here
		// because I believe that requires us to download all
		// contacts in order to feed the timestamp to the hashtable
		// function... hashtable is more suited to a local access,
		// instead of internet access.
		OSyncChangeType ct = OSYNC_CHANGE_TYPE_UNKNOWN;
		if( gcal_contact_is_deleted(contact) ) {
			ct = OSYNC_CHANGE_TYPE_DELETED;

			// remember this item as deleted
			if( !osync_sink_state_set(state_db, url, "", &state_db_error) ) {
				msg = "Error setting state_db with url";
				goto error;
			}
			if( slow_sync || !seen || strlen(seen) == 0 ) {
				// in slow sync mode, we don't care about
				// deleted objects
				continue;
			}
		}
		else {
			if( !slow_sync && seen && strlen(seen) > 0 ) {
				// we've seen this object before
				ct = OSYNC_CHANGE_TYPE_MODIFIED;
			}
			else {
				ct = OSYNC_CHANGE_TYPE_ADDED;
			}

			// the etag will have changed for MODIFIED, and
			// it's a new item if ADDED, so save the url/etag 
			// string either way
			// FIXME - should perhaps set this only after
			// success, such as in the done() plugin call
			if( !osync_sink_state_set(state_db, url, etag, &state_db_error) ) {
				msg = "Error setting state_db with url/etag";
				goto error;
			}
		}

		// create change object
		chg = osync_change_new(&error);
		if( !chg )
			goto cleanup;

		// setup the change
		osync_change_set_uid(chg, url);
		osync_change_set_hash(chg, gcal_contact_get_updated(contact));
		osync_change_set_changetype(chg, ct);

		// fill in the data
		if( ct != OSYNC_CHANGE_TYPE_DELETED ) {
			raw_xml = gcal_contact_get_xml(contact);
			if( xslt_transform(gdata->xslt_google2osync, raw_xml) ) {
				osync_change_unref(chg);
				goto error;
			}

			raw_xml = (char*) gdata->xslt_google2osync->xml_str;
			odata = osync_data_new(strdup(raw_xml),
					       strlen(raw_xml),
					       gdata->format, &error);
			if( !odata ) {
				osync_change_unref(chg);
				goto cleanup;
			}
		}
		else {
			// deleted changes need empty data sets
			odata = osync_data_new(NULL, 0, gdata->format, &error);
			if( !odata ) {
				osync_change_unref(chg);
				goto cleanup;
			}
		}

		osync_data_set_objtype(odata,
				osync_objtype_sink_get_name(sink));
		osync_change_set_data(chg, odata);
		osync_data_unref(odata);

		osync_context_report_change(ctx, chg);
		osync_change_unref(chg);
	}

exit:
	osync_context_report_success(ctx);
	goto cleanup;

error:
	osync_context_report_error(ctx, OSYNC_ERROR_GENERIC, "%s", msg);

cleanup:
	osync_error_unref(&error);
	gcal_cleanup_contacts(&all_contacts);

	// osync_sink_state_get uses osync_strdup
	osync_free(timestamp);

	if (seen)
		osync_free(seen);
}

static void gc_commit_change_calendar(OSyncObjTypeSink *sink,
				OSyncPluginInfo *info, OSyncContext *ctx,
				OSyncChange *change, void *data)
{
	osync_trace(TRACE_ENTRY, "%s(%p, %p, %p, %p, %p)", __func__, sink,
						info, ctx, change, data);
	osync_trace(TRACE_INTERNAL, "hello, from calendar!\n");
	struct gc_gdata *gdata = data;
	gcal_event_t event = NULL;
	unsigned int size;
	int result = 55555; // something odd for the logs
	char *osync_xml = NULL, *msg = NULL, *raw_xml = NULL, *updated_event = NULL;
	char *etag = NULL;
	OSyncData *odata = NULL;
	OSyncError *state_db_error = NULL;
	OSyncSinkStateDB *state_db = NULL;

	state_db = osync_objtype_sink_get_state_db(sink);
	if( !state_db ) {
		msg = "Cannot start state_db!";
		goto error;
	}

	odata = osync_change_get_data(change);
	if( !odata ) {
		msg = "Cannot get raw data from change obj!\n";
		goto error;
	}

	// transform data, only for ADD / MODIFY
	if( osync_change_get_changetype(change) != OSYNC_CHANGE_TYPE_DELETED ) {
		osync_data_get_data(odata, &osync_xml, &size);
		if( !osync_xml ) {
			msg = "Failed getting xml from xmlobj!\n";
			goto error;
		}

		// Convert to gdata format
		result = xslt_transform(gdata->xslt_osync2google, osync_xml);
		if( result ) {
			msg = "Failed converting from osync xmlevent to gcalendar\n";
			osync_trace(TRACE_INTERNAL, "--- osync_uid: %s",
						osync_change_get_uid(change));
			osync_trace(TRACE_INTERNAL,"Failed converting from osync xmlevent to gcalendar: %u, %s",
						size, osync_xml);
			goto error;
		}

		osync_trace(TRACE_INTERNAL, "--- transformed xml: %s",
				(char*) gdata->xslt_osync2google->xml_str);

		raw_xml = vtime2gtime((char*)gdata->xslt_osync2google->xml_str);
		osync_trace(TRACE_INTERNAL, "--- gtime adjusted: %s", raw_xml);
	}

	// check state_db for id to see if we've seen this
	// one before, and grab the etag if so
	if( osync_change_get_uid(change) ) {
		etag = osync_sink_state_get(state_db,
			osync_change_get_uid(change), &state_db_error);
	}

	switch( osync_change_get_changetype(change) )
	{
	case OSYNC_CHANGE_TYPE_ADDED:
		result = gcal_add_xmlentry(gdata->handle, raw_xml,
							&updated_event);
		if( result == -1 ) {
			msg = "Failed adding new event!\n";
			osync_trace(TRACE_INTERNAL, "Failed adding new event! HTTP code: %d, %s, %s\n",
				gcal_status_httpcode(gdata->handle),
				gcal_status_msg(gdata->handle),
				gcal_access_buffer(gdata->handle));
			goto error;
		}

		event = gcal_event_new(updated_event);
		if( !event ) {
			msg = "Failed recovering updated fields!\n";
			goto error;
		}

		osync_trace(TRACE_INTERNAL, "New event added: url = %s etag = %s",
			gcal_event_get_url(event),
			gcal_event_get_etag(event));

		// mark this as "seen"
		if( !osync_sink_state_set(state_db, gcal_event_get_url(event), gcal_event_get_etag(event), &state_db_error) ) {
			msg = "Error setting added state";
			goto error;
		}

		// tell opensync to store the new ID
		osync_change_set_uid(change, gcal_event_get_url(event));
		break;

	case OSYNC_CHANGE_TYPE_MODIFIED:
		if( !etag ) {
			msg = "Trying to modify an unknown entry!";
			goto error;
		}

		result = gcal_update_xmlentry(gdata->handle, raw_xml,
			&updated_event, osync_change_get_uid(change), etag);
		if( result == -1 ) {
			msg = "Failed editing event!\n";
			osync_trace(TRACE_INTERNAL, "Failed editing event: (etag: %s). HTTP code: %d, %s, %s\n",
				etag,
				gcal_status_httpcode(gdata->handle),
				gcal_status_msg(gdata->handle),
				gcal_access_buffer(gdata->handle));
			goto error;
		}

		event = gcal_event_new(updated_event);
		if( !event ) {
			msg = "Failed recovering updated fields!\n";
			goto error;
		}

		osync_trace(TRACE_INTERNAL,"Modified event: url = %s etag = %s",
			gcal_event_get_url(event),
			gcal_event_get_etag(event));

		// make sure that new ID is the same as existing UID
		if( strcmp(osync_change_get_uid(change), gcal_event_get_url(event)) != 0 ) {
			msg = "Opensync UID != modified event ID";
			osync_trace(TRACE_INTERNAL, "Opensync UID != modified event ID: uid = %s, event_id = %s, updated_event = %s",
				osync_change_get_uid(change),
				gcal_event_get_url(event),
				updated_event);
			goto error;
		}

		// mark this as "seen"
		if( !osync_sink_state_set(state_db, gcal_event_get_url(event), gcal_event_get_etag(event), &state_db_error) ) {
			msg = "Error setting modified state";
			goto error;
		}
		break;

	case OSYNC_CHANGE_TYPE_DELETED:
		// create empty event, set the edit_url, and then delete
		event = gcal_event_new(NULL);
		result = gcal_event_set_url(event, osync_change_get_uid(change));
		if( result == -1 ) {
			msg = "Failed setting url for event delete\n";
			goto error;
		}

		result = gcal_erase_event(gdata->handle, event);
		if( result == -1 ) {
			msg = "Failed deleting event!\n";
			osync_trace(TRACE_INTERNAL, "Failed deleting event! HTTP code: %d, %s, %s\n",
				gcal_status_httpcode(gdata->handle),
				gcal_status_msg(gdata->handle),
				gcal_access_buffer(gdata->handle));
			goto error;
		}

		// mark this as "unseen"
		if( !osync_sink_state_set(state_db,
			osync_change_get_uid(change), "", &state_db_error) )
		{
			msg = "Error setting modified state";
			goto error;
		}
		break;

	default:
		msg = "Unknown change type";
		goto error;
	}

	if( event && gcal_event_get_updated(event) ) {
		// update the timestamp
		if( gdata->timestamp ) {
			// only if newer
			if( timestamp_cmp(gcal_event_get_updated(event), gdata->timestamp) > 0 ) {
				free(gdata->timestamp);
				gdata->timestamp = strdup(gcal_event_get_updated(event));
			}
		}
		else {
			gdata->timestamp = strdup(gcal_event_get_updated(event));
		}

		// error check
		if (!gdata->timestamp) {
			msg = "Failed copying contact timestamp!\n";
			goto error;
		}
	}

	osync_context_report_success(ctx);
	osync_trace(TRACE_EXIT, "%s", __func__);

	goto cleanup;

error:
	osync_context_report_error(ctx, OSYNC_ERROR_GENERIC, "%s", msg);
	osync_trace(TRACE_EXIT, "%s:%sResult code: %d", __func__, msg, result);

cleanup:
	if (updated_event)
		free(updated_event);
	if (event)
		gcal_event_delete(event);
	if (raw_xml)
		free(raw_xml);
	if (etag)
		free(etag);
}

static void gc_commit_change_contact(OSyncObjTypeSink *sink,
				OSyncPluginInfo *info, OSyncContext *ctx,
				OSyncChange *change, void *data)
{
	osync_trace(TRACE_ENTRY, "%s(%p, %p, %p, %p, %p)", __func__, sink,
					info, ctx, change, data);
	osync_trace(TRACE_INTERNAL, "hello, from contacts!\n");

	struct gc_gdata *gdata = data;
	gcal_contact_t contact = NULL;
	unsigned int size;
	int result;
	char *osync_xml = NULL, *msg = NULL, *raw_xml = NULL, *updated_contact = NULL;
	OSyncData *odata = NULL;

	if (!(odata = osync_change_get_data(change))) {
		msg = "Cannot get raw data from change obj!\n";
		goto error;
	}

	osync_data_get_data(odata, &osync_xml, &size);
	if (!osync_xml) {
		msg = "Failed getting xml from xmlobj!\n";
		goto error;
	}

	// Convert to gdata format
	if ((result = xslt_transform(gdata->xslt_google2osync, osync_xml))) {
		msg = "Failed converting from osync xmlcontact to gcontact\n";
		goto error;
	}
	raw_xml = vtime2gtime( (char*) gdata->xslt_google2osync->xml_str );

	osync_trace(TRACE_INTERNAL, "osync: %s\ngcont: %s\n\n", osync_xml, raw_xml);

	switch (osync_change_get_changetype(change)) {
		case OSYNC_CHANGE_TYPE_ADDED:
			result = gcal_add_xmlentry(gdata->handle, raw_xml, &updated_contact);
			if (result == -1) {
				msg = "Failed adding new contact!\n";
				result = gcal_status_httpcode(gdata->handle);
				goto error;
			}

			if (!(contact = gcal_contact_new(updated_contact))) {
				msg = "Failed recovering updated fields!\n";
				goto error;
			}
		break;

		case OSYNC_CHANGE_TYPE_MODIFIED:
			result = gcal_update_xmlentry(gdata->handle,
				raw_xml, &updated_contact, NULL, NULL);
			if (result == -1) {
				msg = "Failed editing contact!\n";
				goto error;
			}

			if (!(contact = gcal_contact_new(updated_contact))) {
				msg = "Failed recovering updated fields!\n";
				goto error;
			}
		break;

		case OSYNC_CHANGE_TYPE_DELETED:
			result = gcal_erase_xmlentry(gdata->handle, raw_xml);
			if (result == -1) {
				msg = "Failed deleting contact!\n";
				goto error;
			}
		break;

		default:
			osync_context_report_error(ctx, OSYNC_ERROR_NOT_SUPPORTED,
						   "Unknown change type");
			goto error;
		break;
	}

	if (updated_contact)
		free(updated_contact);

	if (contact) {
		// update the timestamp
		if (gdata->timestamp)
			free(gdata->timestamp);
		gdata->timestamp = strdup(gcal_contact_get_updated(contact));
		if (!gdata->timestamp) {
			msg = "Failed copying contact timestamp!\n";
			goto error;
		}

		// FIXME: not sure if this works
		// Inform the new ID
		osync_change_set_uid(change, gcal_contact_get_url(contact));
		gcal_contact_delete(contact);
	}

	//free(osync_xml);

	osync_context_report_success(ctx);
	osync_trace(TRACE_EXIT, "%s", __func__);

	return;

error:
	if (updated_contact)
		free(updated_contact);
	if (raw_xml)
		free(raw_xml);

	osync_context_report_error(ctx, OSYNC_ERROR_GENERIC, "%s", msg);
	osync_trace(TRACE_EXIT, "%s:%sHTTP code: %d", __func__, msg, result);
}

static void gc_sync_done(OSyncObjTypeSink *sink, OSyncPluginInfo *info,
			OSyncContext *ctx, void *data)
{
	osync_trace(TRACE_ENTRY, "%s(%p, %p, %p)", __func__, data, info, ctx);
	struct gc_gdata *gdata = data;
	OSyncError *state_db_error;

	if( gdata->handle && gdata->timestamp ) {
		osync_trace(TRACE_INTERNAL, "query updated timestamp: %s: %s\n",
				gdata->timestamp_name, gdata->timestamp);
		osync_sink_state_set(osync_objtype_sink_get_state_db(sink),
				gdata->timestamp_name, gdata->timestamp,
				&state_db_error);
	}

	osync_context_report_success(ctx);
}

static void gc_disconnect(OSyncObjTypeSink *sink, OSyncPluginInfo *info,
			OSyncContext *ctx, void *data)
{
	osync_trace(TRACE_ENTRY, "%s(%p, %p, %p)", __func__, data, info, ctx);
	osync_context_report_success(ctx);
	osync_trace(TRACE_EXIT, "%s", __func__);
}


/////////////////////////////////////////////////////////////////////////////
// Plugin API

static void *gc_initialize(OSyncPlugin *plugin,
			   OSyncPluginInfo *info,
			   OSyncError **error)
{
	osync_trace(TRACE_ENTRY, "%s(%p, %p, %p)", __func__, plugin, info, error);
	struct gc_plgdata *plgdata;
	OSyncPluginConfig *config;
	OSyncList *resources;
	OSyncList *r;

	plgdata = osync_try_malloc0(sizeof(struct gc_plgdata), error);
	config = osync_plugin_info_get_config(info);
	if( (!plgdata) || (!config) ) {
		osync_error_set(error, OSYNC_ERROR_GENERIC,
				"Unable to get config data.");
		goto error_freeplg;
	}

	// set parent pointers
	plgdata->cal.plgdata = plgdata;
	plgdata->cont.plgdata = plgdata;

	// set xslt filenames
	plgdata->cal.timestamp_name = "cal_timestamp";
	plgdata->cal.google2osync_file = "gcal2osync.xslt";
	plgdata->cal.osync2google_file = "osync2gcal.xslt";
	plgdata->cont.timestamp_name = "cont_timestamp";
	plgdata->cont.google2osync_file = "gcont2osync.xslt";
	plgdata->cont.osync2google_file = "osync2gcont.xslt";

	// grab config dir
	plgdata->xslt_path = strdup(osync_plugin_get_default_configdir());
	if( !plgdata->xslt_path )
		goto error_freeplg;

	// create a gcal handle for each objtype available
	resources = osync_plugin_config_get_resources(config);
	for( r = resources; r; r = r->next ) {
		osync_trace(TRACE_INTERNAL, "field: %s\n",
			osync_plugin_resource_get_objtype(r->data));

		if( !strcmp(osync_plugin_resource_get_objtype(r->data), "event") ) {
			plgdata->cal.handle = gcal_new(GCALENDAR);
			if( !plgdata->cal.handle )
				goto error_freeplg;
			else {
				osync_trace(TRACE_INTERNAL,
						"\tcreated calendar obj!\n");
				gcal_set_store_xml(plgdata->cal.handle, 1);
			}
		}

		if( !strcmp(osync_plugin_resource_get_objtype(r->data), "contact") ) {
			plgdata->cont.handle = gcal_new(GCONTACT);
			if( !plgdata->cont.handle )
				goto error_freeplg;
			else {
				osync_trace(TRACE_INTERNAL,
						"\tcreated contact obj!\n");
				gcal_set_store_xml(plgdata->cont.handle, 1);
			}
		}

	}


	// Fetch username
	OSyncPluginAuthentication *optauth = NULL;
	optauth = osync_plugin_config_get_authentication(config);
	if( osync_plugin_authentication_option_is_supported(optauth,
				OSYNC_PLUGIN_AUTHENTICATION_USERNAME) ) {
		const char *user =
			osync_plugin_authentication_get_username(optauth);
		if( !user )
			goto error_freeplg;

		plgdata->username = strdup(user);
		if( !plgdata->username )
			goto error_freeplg;
	}
	else {
		goto error_freeplg;
	}

	// Fetch password
	if( osync_plugin_authentication_option_is_supported(optauth,
				OSYNC_PLUGIN_AUTHENTICATION_PASSWORD) ) {
		const char *pass =
			osync_plugin_authentication_get_password(optauth);
		if( !pass )
			goto error_freeplg;

		plgdata->password = strdup(pass);
		if( !plgdata->password )
			goto error_freeplg;
	}
	else {
		goto error_freeplg;
	}

	// TODO: get proxy/calendar title/resources/etc


	// Register calendar sink
	OSyncObjTypeSink *sink = NULL;
	sink = osync_plugin_info_find_objtype(info, "event");
	if( !sink ) {
		osync_trace(TRACE_ERROR, "%s", "Failed to find objtype event!");
	}
	if( sink && osync_objtype_sink_is_enabled(sink) && plgdata->cal.handle ) {

		osync_trace(TRACE_INTERNAL, "\tcreating calendar sink...\n");
		OSyncFormatEnv *formatenv = osync_plugin_info_get_format_env(info);
		plgdata->cal.format = osync_format_env_find_objformat(formatenv, "xmlformat-event-doc");
		if (!plgdata->cal.format) {
			osync_trace(TRACE_ERROR, "%s", "Failed to find objformat xmlformat-event!");
			goto error_freeplg;
		}
		osync_objformat_ref(plgdata->cal.format);


		osync_objtype_sink_set_connect_func(sink, gc_connect);
		osync_objtype_sink_set_disconnect_func(sink, gc_disconnect);
		osync_objtype_sink_set_get_changes_func(sink,
						gc_get_changes_calendar);
		osync_objtype_sink_set_commit_func(sink,
						gc_commit_change_calendar);
		osync_objtype_sink_set_sync_done_func(sink, gc_sync_done);


		osync_objtype_sink_set_userdata(sink, &plgdata->cal);
 		osync_objtype_sink_enable_state_db(sink, TRUE);
	}





	// Register contact sink
	sink = NULL;
	sink = osync_plugin_info_find_objtype(info, "contact");
	if( !sink ) {
		osync_trace(TRACE_ERROR, "%s", "Failed to find objtype contact!");
	}
	if( sink && osync_objtype_sink_is_enabled(sink) && plgdata->cont.handle ) {

		osync_trace(TRACE_INTERNAL, "\tcreating contact sink...\n");
		OSyncFormatEnv *formatenv = osync_plugin_info_get_format_env(info);
		plgdata->cont.format = osync_format_env_find_objformat(formatenv, "xmlformat-contact-doc");
		if (!plgdata->cont.format) {
			osync_trace(TRACE_ERROR, "%s", "Failed to find objformat xmlformat-contact!");
			goto error_freeplg;
		}
		osync_objformat_ref(plgdata->cont.format);


		osync_objtype_sink_set_connect_func(sink, gc_connect);
		osync_objtype_sink_set_disconnect_func(sink, gc_disconnect);
		osync_objtype_sink_set_get_changes_func(sink,
						gc_get_changes_contact);
		osync_objtype_sink_set_commit_func(sink,
						gc_commit_change_contact);
		osync_objtype_sink_set_sync_done_func(sink, gc_sync_done);


		osync_objtype_sink_set_userdata(sink, &plgdata->cont);
 		osync_objtype_sink_enable_state_db(sink, TRUE);
	}


	if( plgdata->cal.handle ) {
		plgdata->cal.xslt_google2osync = xslt_new();
		plgdata->cal.xslt_osync2google = xslt_new();
		if (!plgdata->cal.xslt_google2osync || !plgdata->cal.xslt_osync2google)
			goto error_freeplg;
		else
			osync_trace(TRACE_INTERNAL, "\tsucceed creating xslt_gcal!\n");
	}

	if( plgdata->cont.handle ) {
		plgdata->cont.xslt_google2osync = xslt_new();
		plgdata->cont.xslt_osync2google = xslt_new();
		if (!plgdata->cont.xslt_google2osync || !plgdata->cont.xslt_osync2google)
			goto error_freeplg;
		else
			osync_trace(TRACE_INTERNAL, "\tsucceed creating xslt_gcont!\n");
	}

	osync_trace(TRACE_EXIT, "%s", __func__);

	return plgdata;

error_freeplg:
	if (plgdata)
		free_plg(plgdata);
	osync_trace(TRACE_EXIT_ERROR, "%s: %s", __func__, osync_error_print(error));
	return NULL;
}

static osync_bool gc_discover(OSyncPluginInfo *info, void *data, OSyncError **error)
{
	osync_trace(TRACE_ENTRY, "%s(%p, %p, %p)", __func__, data, info, error);

	OSyncList *sinks = osync_plugin_info_get_objtype_sinks(info);
	OSyncList *s = sinks;
	for( ; s; s = s->next ) {
		OSyncObjTypeSink *sink = (OSyncObjTypeSink*) s->data;
		osync_objtype_sink_set_available(sink, TRUE);
	}

	OSyncVersion *version = osync_version_new(error);
	osync_version_set_plugin(version, "google-data");
	osync_plugin_info_set_version(info, version);
	osync_version_unref(version);

	osync_trace(TRACE_EXIT, "%s", __func__);
	return TRUE;
}

static void gc_finalize(void *data)
{
	osync_trace(TRACE_ENTRY, "%s(%p)", __func__, data);
	struct gc_plgdata *plgdata = data;

	free_plg(plgdata);
	osync_trace(TRACE_EXIT, "%s", __func__);
}

osync_bool get_sync_info(OSyncPluginEnv *env, OSyncError **error)
{
	osync_trace(TRACE_ENTRY, "%s(%p, %p)", __func__, env, error);
	OSyncPlugin *plugin = osync_plugin_new(error);
	if( !plugin )
		goto error;

	osync_plugin_set_name(plugin, "google-data");
	osync_plugin_set_longname(plugin, "Google calendar/plugin");
	osync_plugin_set_description(plugin,
		"Google calendar and contacts plugin");

	osync_plugin_set_initialize(plugin, gc_initialize);
	osync_plugin_set_finalize(plugin, gc_finalize);
	osync_plugin_set_discover(plugin, gc_discover);
	osync_plugin_set_start_type(plugin, OSYNC_START_TYPE_PROCESS);

	if( !osync_plugin_env_register_plugin(env, plugin, error) )
		goto error;
	osync_plugin_unref(plugin);

	osync_trace(TRACE_EXIT, "%s", __func__);
	return TRUE;

error:
	osync_trace(TRACE_EXIT_ERROR, "Unable to register: %s",
				osync_error_print(error));
	return FALSE;
}

int get_version(void)
{
	return 1;
}

