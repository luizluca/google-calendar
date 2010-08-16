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

static void gc_connect_calendar(OSyncObjTypeSink *sink, OSyncPluginInfo *info,
				OSyncContext *ctx, void *data);
static void gc_connect_contact(OSyncObjTypeSink *sink, OSyncPluginInfo *info,
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

static int timestamp_cmp(char *timestamp1, char *timestamp2)
{
	// timestamp (RFC3339) formating string
	char format[] = "%FT%T";
	struct tm first, second;
	time_t t_first, t_second;
	int result = 0;

	if (!timestamp1 || !timestamp2)
		return 1;

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


struct gc_plgdata
{
	char *url;
	char *username;
	char *password;
	char *timezone;
	char *xslt_path;
	// libgcal resources
	char *cal_timestamp;
	char *cont_timestamp;
	gcal_t calendar;
	gcal_t contacts;
	struct gcal_event_array all_events;
	struct gcal_contact_array all_contacts;
	// calendar sink/format
	OSyncObjFormat *gcal_format;
	// contact sink/format
	OSyncObjFormat *gcont_format;
	// XSLT context resource struct
	// google -> osync
	struct xslt_resources *xslt_ctx_gcal;
	struct xslt_resources *xslt_ctx_gcont;
	// osync -> google
	struct xslt_resources *xslt_ctx_ocal;
	struct xslt_resources *xslt_ctx_ocont;
};

static void free_plg(struct gc_plgdata *plgdata)
{
	if (plgdata->calendar) {
		gcal_delete(plgdata->calendar);
		gcal_cleanup_events(&(plgdata->all_events));
	}
	if (plgdata->contacts) {
		gcal_delete(plgdata->contacts);
		gcal_cleanup_contacts(&(plgdata->all_contacts));
	}

	if (plgdata->xslt_path)
		free(plgdata->xslt_path);
	if (plgdata->xslt_ctx_gcal)
		xslt_delete(plgdata->xslt_ctx_gcal);
	if (plgdata->xslt_ctx_gcont)
		xslt_delete(plgdata->xslt_ctx_gcont);
	if (plgdata->xslt_ctx_ocal)
		xslt_delete(plgdata->xslt_ctx_ocal);
	if (plgdata->xslt_ctx_ocont)
		xslt_delete(plgdata->xslt_ctx_ocont);
	if (plgdata->cal_timestamp)
		free(plgdata->cal_timestamp);
	if (plgdata->cont_timestamp)
		free(plgdata->cont_timestamp);
	if (plgdata->timezone)
		free(plgdata->timezone);
	if (plgdata->url)
		xmlFree(plgdata->url);
	if (plgdata->username)
		xmlFree(plgdata->username);
	if (plgdata->password)
		xmlFree(plgdata->password);
	if (plgdata->gcal_format)
		osync_objformat_unref(plgdata->gcal_format);
	g_free(plgdata);
}

static void gc_connect_calendar(OSyncObjTypeSink *sink, OSyncPluginInfo *info,
				OSyncContext *ctx, void *data)
{
	osync_trace(TRACE_ENTRY, "%s(%p, %p, %p)", __func__, data, info, ctx);
	int result;
	struct gc_plgdata *plgdata = data;
	OSyncError *error = NULL;
	char buffer[512];

	result = gcal_get_authentication(plgdata->calendar, plgdata->username,
					 plgdata->password);
	if (result == -1)
		goto error;

	// google -> osync
	snprintf(buffer, sizeof(buffer) - 1, "%sgcal2osync.xslt",
		 plgdata->xslt_path);
	if ((result = xslt_initialize(plgdata->xslt_ctx_gcal, buffer)))
		goto error;
	osync_trace(TRACE_INTERNAL, "loaded calendar xslt: %s\n", buffer);

	// osync -> google
	snprintf(buffer, sizeof(buffer) - 1, "%sosync2gcal.xslt",
		 plgdata->xslt_path);
	if ((result = xslt_initialize(plgdata->xslt_ctx_ocal, buffer)))
		goto error;
	osync_trace(TRACE_INTERNAL, "loaded calendar xslt: %s\n", buffer);

	osync_context_report_success(ctx);
	osync_trace(TRACE_EXIT, "%s", __func__);
	return;

error:
	osync_trace(TRACE_INTERNAL,
			"Failed to load gcal2osync.xslt stylesheet!\n");
	osync_error_set(&error, OSYNC_ERROR_GENERIC,
			"Unable load gcal2osync.xslt stylesheet data.");
	osync_context_report_osyncerror(ctx, error);
}

static void gc_connect_contact(OSyncObjTypeSink *sink, OSyncPluginInfo *info,
				OSyncContext *ctx, void *data)
{
	osync_trace(TRACE_ENTRY, "%s(%p, %p, %p)", __func__, data, info, ctx);
	int result;
	struct gc_plgdata *plgdata = data;
	OSyncError *error = NULL;
	char buffer[512];

	result = gcal_get_authentication(plgdata->contacts, plgdata->username,
					 plgdata->password);
	if (result == -1)
		goto error;

	// google -> osync
	snprintf(buffer, sizeof(buffer) - 1, "%sgcont2osync.xslt",
		 plgdata->xslt_path);
	if ((result = xslt_initialize(plgdata->xslt_ctx_gcont, buffer)))
		goto error;
	osync_trace(TRACE_INTERNAL, "loaded contact xslt: %s\n", buffer);

	// osync -> google
	snprintf(buffer, sizeof(buffer) - 1, "%sosync2gcont.xslt",
		 plgdata->xslt_path);
	if ((result = xslt_initialize(plgdata->xslt_ctx_ocont, buffer)))
		goto error;
	osync_trace(TRACE_INTERNAL, "loaded contact xslt: %s\n", buffer);

	osync_context_report_success(ctx);
	osync_trace(TRACE_EXIT, "%s", __func__);
	return;

error:
	osync_trace(TRACE_INTERNAL,
			"Failed to load gcont2osync.xslt stylesheet!\n");
	osync_error_set(&error, OSYNC_ERROR_GENERIC,
			"Unable load gcont2osync.xslt stylesheet data.");
	osync_context_report_osyncerror(ctx, error);
}

static void gc_get_changes_calendar(OSyncObjTypeSink *sink,
			OSyncPluginInfo *info, OSyncContext *ctx,
			osync_bool slow_sync, void *data)
{
	osync_trace(TRACE_ENTRY, "%s(%p, %p, %p)", __func__, data, info, ctx);
	struct gc_plgdata *plgdata = data;
	OSyncError *error = NULL;
	OSyncData *odata = NULL;
	OSyncChange *chg = NULL;
	int result = 0, i;
	char *timestamp = NULL, *msg = NULL, *raw_xml = NULL;
	gcal_event_t event;
	OSyncError *state_db_error = NULL;
	OSyncSinkStateDB *state_db = NULL;

	state_db = osync_objtype_sink_get_state_db(sink);
	if( !state_db )
		goto error;

	timestamp = osync_sink_state_get(state_db, "cal_timestamp",
						&state_db_error);
	if (!timestamp) {
		msg = "gcalendar: Anchor returned is NULL!";
		goto error;
	}

	osync_trace(TRACE_INTERNAL, "timestamp is: '%s'\n", timestamp);

	if (slow_sync || strlen(timestamp) == 0) {
		osync_trace(TRACE_INTERNAL, "\n\t\tgcal: slow sync, or first time\n");
		result = gcal_get_events(plgdata->calendar, &(plgdata->all_events));

	} else {
		result = gcal_get_updated_events(plgdata->calendar,
						 &(plgdata->all_events),
						 timestamp);
	}

	if (result) {
		msg = "Failed getting events!";
		goto error;
	}

	osync_trace(TRACE_INTERNAL, "gcalendar: got them all!\n");
	if (plgdata->all_events.length == 0) {
		osync_trace(TRACE_INTERNAL, "gcalendar: no changes...\n");
		goto exit;
	} else {
		osync_trace(TRACE_INTERNAL, "gcalendar: changes count: %d\n",
			    plgdata->all_events.length);
	}

	// Calendar returns most recently updated event as first element
	for (i = 0; i < plgdata->all_events.length; ++i) {
		// grab the next event object
		event = gcal_event_element(&(plgdata->all_events), i);
		if (!event) {
			osync_trace(TRACE_INTERNAL, "Cannot access updated event %d", i);
			goto error;
		}

		// save first timestamp as new "done" mark
		if (i == 0) {
			if (plgdata->cal_timestamp)
				free(plgdata->cal_timestamp);
			plgdata->cal_timestamp = strdup(gcal_event_get_updated(event));
			if (!plgdata->cal_timestamp) {
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
		const char *id = gcal_event_get_id(event);

		// determine changetype - we do not use osync_hashtable here
		// because I believe that requires us to download all
		// events in order to feed the timestamp to the hashtable
		// function... hashtable is more suited to a local access,
		// instead of internet access.
		OSyncChangeType ct = OSYNC_CHANGE_TYPE_UNKNOWN;
		if( gcal_event_is_deleted(event) ) {
			ct = OSYNC_CHANGE_TYPE_DELETED;
			if( !osync_sink_state_set(state_db, id, "0", &state_db_error) ) {
				msg = "Error setting state_db for id";
				goto error;
			}
			if( slow_sync ) {
				// in slow sync mode, we don't care about
				// deleted objects
				continue;
			}
		}
		else {
			// not deleted, so either ADDED or MODIFIED...
			// check state_db for id to see if we've seen this
			// one before
			const char *seen = osync_sink_state_get(state_db,
							id, &state_db_error);
			if( !seen ) {
				msg = "sink_state_get returned NULL";
				goto error;
			}

			if( !slow_sync && seen[0] == '1' ) {
				// we've seen this object before
				ct = OSYNC_CHANGE_TYPE_MODIFIED;
			}
			else {
				ct = OSYNC_CHANGE_TYPE_ADDED;
				if( !osync_sink_state_set(state_db, id, "1", &state_db_error) ) {
					msg = "Error setting state_db for id";
					goto error;
				}
			}
		}

		// create change object
		chg = osync_change_new(&error);
		if( !chg )
			goto cleanup;

		// setup the change
		osync_change_set_uid(chg, id);
		osync_change_set_hash(chg, gcal_event_get_updated(event));
		osync_change_set_changetype(chg, ct);

		// fill in the data
		if( ct != OSYNC_CHANGE_TYPE_DELETED ) {
			raw_xml = gcal_event_get_xml(event);
			if( xslt_transform(plgdata->xslt_ctx_gcal, raw_xml) ) {
				osync_change_unref(chg);
				goto error;
			}

			raw_xml = (char*) plgdata->xslt_ctx_gcal->xml_str;
			odata = osync_data_new(strdup(raw_xml),
					       strlen(raw_xml),
					       plgdata->gcal_format, &error);
			if( !odata ) {
				osync_change_unref(chg);
				goto cleanup;
			}

			osync_data_set_objtype(odata,
					osync_objtype_sink_get_name(sink));
			osync_change_set_data(chg, odata);
			osync_data_unref(odata);
		}

		osync_context_report_change(ctx, chg);
		osync_change_unref(chg);
	}


exit:
	// osync_sink_state_get uses osync_strdup
	osync_free(timestamp);
	osync_context_report_success(ctx);
	return;

cleanup:
	osync_error_unref(&error);
	// osync_sink_state_get uses osync_strdup
	osync_free(timestamp);

error:
	osync_context_report_error(ctx, OSYNC_ERROR_GENERIC, msg);

}


static void gc_get_changes_contact(OSyncObjTypeSink *sink,
			OSyncPluginInfo *info, OSyncContext *ctx,
			osync_bool slow_sync, void *data)
{
	osync_trace(TRACE_ENTRY, "%s(%p, %p, %p)", __func__, data, info, ctx);
	char buffer[512];
	struct gc_plgdata *plgdata = data;
	char slow_sync_flag = 0;
	OSyncError *error = NULL;
	OSyncData *odata = NULL;
	OSyncChange *chg = NULL;
	int result = 0, i;
	char *timestamp = NULL, *msg, *raw_xml = NULL;
	gcal_contact_t contact;
	OSyncError *state_db_error = NULL;

	if (!(osync_objtype_sink_get_state_db(sink)))
		goto error;

	timestamp = osync_sink_state_get(osync_objtype_sink_get_state_db(sink),
					  "cont_timestamp", &state_db_error);
	if (!timestamp) {
		msg = "gcontact: Anchor returned is NULL!";
		goto error;
	}

	if (strlen(timestamp) > 0)
		osync_trace(TRACE_INTERNAL, "timestamp is: %s\n", timestamp);
	else
		osync_trace(TRACE_INTERNAL, "first sync!\n");

	if (slow_sync) {
		osync_trace(TRACE_INTERNAL, "\n\t\tgcont: Client asked for slow syncing...\n");
		slow_sync_flag = 1;
		result = gcal_get_contacts(plgdata->contacts, &(plgdata->all_contacts));

	} else {
		osync_trace(TRACE_INTERNAL, "\n\t\tgcont: Client asked for fast syncing...\n");
		gcal_deleted(plgdata->contacts, SHOW);
		result = gcal_get_updated_contacts(plgdata->contacts,
						   &(plgdata->all_contacts),
						   timestamp);
	}

	if (result) {
		msg = "Failed getting contacts!";
		goto error;
	}

	osync_trace(TRACE_INTERNAL, "gcontact: got them all!\n");
	if (plgdata->all_contacts.length == 0) {
		osync_trace(TRACE_INTERNAL, "gcontact: no changes...\n");
		goto no_changes;
	} else
		osync_trace(TRACE_INTERNAL, "gcontact: changes count: %d\n",
			    plgdata->all_contacts.length);

	// Contacts returns most recently updated entry as last element
	contact = gcal_contact_element(&(plgdata->all_contacts),
				       (plgdata->all_contacts.length - 1));
	if (!contact) {
		msg = "Cannot access last updated contact!\n";
		goto error;
	}
	plgdata->cont_timestamp = strdup(gcal_contact_get_updated(contact));
	if (!plgdata->cont_timestamp) {
		msg = "Failed copying contact timestamp!\n";
		goto error;
	}

	for (i = 0; i < plgdata->all_contacts.length; ++i) {
		contact = gcal_contact_element(&(plgdata->all_contacts), i);
		if (!contact)
			goto error;

		osync_trace(TRACE_INTERNAL, "gcontact: timestamp:%s\tcontact:%s\n",
			    timestamp, gcal_contact_get_updated(contact));
		// Workaround for inclusive returned results
		if ((timestamp_cmp(timestamp, gcal_contact_get_updated(contact)) == 0)
		    && !slow_sync_flag
		    && !gcal_contact_is_deleted(contact)) {
			osync_trace(TRACE_INTERNAL, "gcontact: old contact.");
			continue;
		} else
			osync_trace(TRACE_INTERNAL, "gcontact: new or deleted contact!");

		raw_xml = gcal_contact_get_xml(contact);
		if ((result = xslt_transform(plgdata->xslt_ctx_gcont,
					     raw_xml)))
			goto error;

		raw_xml = (char*) plgdata->xslt_ctx_gcont->xml_str;
		odata = osync_data_new(strdup(raw_xml),
				       strlen(raw_xml),
				       plgdata->gcont_format, &error);
		if (!odata)
			goto cleanup;

		if (!(chg = osync_change_new(&error)))
			goto cleanup;
		osync_data_set_objtype(odata, osync_objtype_sink_get_name(sink));
		osync_change_set_data(chg, odata);
		osync_data_unref(odata);

		osync_change_set_uid(chg, gcal_contact_get_id(contact));

		if (slow_sync_flag)
			osync_change_set_changetype(chg, OSYNC_CHANGE_TYPE_ADDED);
		else
			if (gcal_contact_is_deleted(contact)) {
				osync_change_set_changetype(chg, OSYNC_CHANGE_TYPE_DELETED);
				osync_trace(TRACE_INTERNAL, "deleted entry!");
			}
			else
				osync_change_set_changetype(chg, OSYNC_CHANGE_TYPE_MODIFIED);

		osync_context_report_change(ctx, chg);
		osync_change_unref(chg);
	}

no_changes:

	// Load XSLT style to convert osync xmlformat-contact --> gdata
	snprintf(buffer, sizeof(buffer) - 1, "%sosync2gcont.xslt",
		 plgdata->xslt_path);
	if ((result = xslt_initialize(plgdata->xslt_ctx_gcont, buffer))) {
		msg = "Cannot initialize new XSLT!\n";
		goto error;
	}

	osync_trace(TRACE_INTERNAL, "\ndone contact: %s\n", buffer);

//exit:
	// osync_sink_state_get uses osync_strdup
	osync_free(timestamp);
	osync_context_report_success(ctx);
	return;

cleanup:
	osync_error_unref(&error);
	// osync_sink_state_get uses osync_strdup
	osync_free(timestamp);

error:
	osync_context_report_error(ctx, OSYNC_ERROR_GENERIC, msg);
}

static void gc_commit_change_calendar(OSyncObjTypeSink *sink,
				OSyncPluginInfo *info, OSyncContext *ctx,
				OSyncChange *change, void *data)
{
	osync_trace(TRACE_ENTRY, "%s(%p, %p, %p, %p, %p)", __func__, sink,
						info, ctx, change, data);
	osync_trace(TRACE_INTERNAL, "hello, from calendar!\n");
	struct gc_plgdata *plgdata = data;
	gcal_event_t event = NULL;
	unsigned int size;
	int result = 55555; // something odd for the logs
	char *osync_xml = NULL, *msg = NULL, *raw_xml = NULL, *updated_event = NULL;
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

	osync_data_get_data(odata, &osync_xml, &size);
	if( !osync_xml ) {
		msg = "Failed getting xml from xmlobj!\n";
		goto error;
	}

	// Convert to gdata format
	result = xslt_transform(plgdata->xslt_ctx_ocal, osync_xml);
	if( result ) {
		msg = "Failed converting from osync xmlevent to gcalendar\n";
		goto error;
	}

	raw_xml = vtime2gtime( (char*) plgdata->xslt_ctx_gcal->xml_str );

	osync_trace(TRACE_EXIT, "osync: %s\ngcont: %s\n\n", osync_xml, raw_xml);

	switch( osync_change_get_changetype(change) )
	{
	case OSYNC_CHANGE_TYPE_ADDED:
		result = gcal_add_xmlentry(plgdata->calendar, raw_xml,
							&updated_event);
		if( result == -1 ) {
			msg = "Failed adding new event!\n";
			result = gcal_status_httpcode(plgdata->calendar);
			goto error;
		}

		event = gcal_event_new(updated_event);
		if( !event ) {
			msg = "Failed recovering updated fields!\n";
			goto error;
		}

		// mark this as "seen"
		if( !osync_sink_state_set(state_db, gcal_event_get_id(event), "1", &state_db_error) ) {
			msg = "Error setting added state";
			goto error;
		}
		break;

	case OSYNC_CHANGE_TYPE_MODIFIED:
		result = gcal_update_xmlentry(plgdata->calendar, raw_xml,
						&updated_event, NULL, NULL);
		if( result == -1 ) {
			msg = "Failed editing event!\n";
			goto error;
		}

		event = gcal_event_new(updated_event);
		if( !event ) {
			msg = "Failed recovering updated fields!\n";
			goto error;
		}

		// mark this as "seen"
		if( !osync_sink_state_set(state_db, gcal_event_get_id(event), "1", &state_db_error) ) {
			msg = "Error setting modified state";
			goto error;
		}
		break;

	case OSYNC_CHANGE_TYPE_DELETED:
		result = gcal_erase_xmlentry(plgdata->calendar, raw_xml);
		if( result == -1 ) {
			msg = "Failed deleting event!\n";
			goto error;
		}

		// mark this as "unseen"
		if( !osync_sink_state_set(state_db,
			osync_change_get_uid(change), "0", &state_db_error) )
		{
			msg = "Error setting modified state";
			goto error;
		}
		break;

	default:
		osync_context_report_error(ctx, OSYNC_ERROR_NOT_SUPPORTED,
					   "Unknown change type");
		msg = "Unknown change type";
		goto error;
		break;
	}

	if (updated_event)
		free(updated_event);

	if (event) {
		// update the timestamp
		if( plgdata->cal_timestamp ) {
			// only if newer
			if( timestamp_cmp(gcal_event_get_updated(event), plgdata->cal_timestamp) > 0 ) {
				free(plgdata->cal_timestamp);
				plgdata->cal_timestamp = strdup(gcal_event_get_updated(event));
			}
		}
		else {
			plgdata->cal_timestamp = strdup(gcal_event_get_updated(event));
		}

		// error check
		if (!plgdata->cal_timestamp) {
			msg = "Failed copying contact timestamp!\n";
			goto error;
		}

		// Inform the new ID
		osync_change_set_uid(change, gcal_event_get_id(event));
		gcal_event_delete(event);

	}

	//	free(osync_xml);

	osync_context_report_success(ctx);
	osync_trace(TRACE_EXIT, "%s", __func__);

	return;
error:
	if (updated_event)
		free(updated_event);
	if (raw_xml)
		free(raw_xml);

	osync_context_report_error(ctx, OSYNC_ERROR_GENERIC, msg);
	osync_trace(TRACE_EXIT, "%s:%sHTTP code: %d", __func__, msg, result);
}

static void gc_commit_change_contact(OSyncObjTypeSink *sink,
				OSyncPluginInfo *info, OSyncContext *ctx,
				OSyncChange *change, void *data)
{
	osync_trace(TRACE_ENTRY, "%s(%p, %p, %p, %p, %p)", __func__, sink,
					info, ctx, change, data);
	osync_trace(TRACE_INTERNAL, "hello, from contacts!\n");

	struct gc_plgdata *plgdata = data;
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
	if ((result = xslt_transform(plgdata->xslt_ctx_gcont, osync_xml))) {
		msg = "Failed converting from osync xmlcontact to gcontact\n";
		goto error;
	}
	raw_xml = vtime2gtime( (char*) plgdata->xslt_ctx_gcont->xml_str );

	osync_trace(TRACE_INTERNAL, "osync: %s\ngcont: %s\n\n", osync_xml, raw_xml);

	switch (osync_change_get_changetype(change)) {
		case OSYNC_CHANGE_TYPE_ADDED:
			result = gcal_add_xmlentry(plgdata->contacts, raw_xml, &updated_contact);
			if (result == -1) {
				msg = "Failed adding new contact!\n";
				result = gcal_status_httpcode(plgdata->contacts);
				goto error;
			}

			if (!(contact = gcal_contact_new(updated_contact))) {
				msg = "Failed recovering updated fields!\n";
				goto error;
			}
		break;

		case OSYNC_CHANGE_TYPE_MODIFIED:
			result = gcal_update_xmlentry(plgdata->contacts,
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
			result = gcal_erase_xmlentry(plgdata->contacts, raw_xml);
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
		if (plgdata->cont_timestamp)
			free(plgdata->cont_timestamp);
		plgdata->cont_timestamp = strdup(gcal_contact_get_updated(contact));
		if (!plgdata->cont_timestamp) {
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

	osync_context_report_error(ctx, OSYNC_ERROR_GENERIC, msg);
	osync_trace(TRACE_EXIT, "%s:%sHTTP code: %d", __func__, msg, result);
}

static void gc_sync_done(OSyncObjTypeSink *sink, OSyncPluginInfo *info,
			OSyncContext *ctx, void *data)
{
	osync_trace(TRACE_ENTRY, "%s(%p, %p, %p)", __func__, data, info, ctx);
	struct gc_plgdata *plgdata = data;
	OSyncError *state_db_error;

	if (plgdata->calendar && plgdata->cal_timestamp) {
		osync_trace(TRACE_INTERNAL, "query updated timestamp: %s\n",
				    plgdata->cal_timestamp);
		osync_sink_state_set(osync_objtype_sink_get_state_db(sink),
				    "cal_timestamp", plgdata->cal_timestamp,
				    &state_db_error);
	}

	if (plgdata->contacts && plgdata->cont_timestamp) {
		osync_trace(TRACE_INTERNAL, "query updated timestamp: %s\n",
				    plgdata->cont_timestamp);
		osync_sink_state_set(osync_objtype_sink_get_state_db(sink),
				    "cont_timestamp", plgdata->cont_timestamp,
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

	plgdata->xslt_path = strdup(osync_plugin_get_default_configdir());
	if( !plgdata->xslt_path )
		goto error_freeplg;

	resources = osync_plugin_config_get_resources(config);
	for( r = resources; r; r = r->next ) {
		osync_trace(TRACE_INTERNAL, "field: %s\n",
			osync_plugin_resource_get_objtype(r->data));

		if( !strcmp(osync_plugin_resource_get_objtype(r->data), "event") ) {
			plgdata->calendar = gcal_new(GCALENDAR);
			if( !plgdata->calendar )
				goto error_freeplg;
			else {
				osync_trace(TRACE_INTERNAL,
						"\tcreated calendar obj!\n");
				gcal_set_store_xml(plgdata->calendar, 1);
			}
		}

		if( !strcmp(osync_plugin_resource_get_objtype(r->data), "contact") ) {
			plgdata->contacts = gcal_new(GCONTACT);
			if( !plgdata->contacts )
				goto error_freeplg;
			else {
				osync_trace(TRACE_INTERNAL,
						"\tcreated contact obj!\n");
				gcal_set_store_xml(plgdata->contacts, 1);
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
	if( sink && osync_objtype_sink_is_enabled(sink) && plgdata->calendar ) {

		osync_trace(TRACE_INTERNAL, "\tcreating calendar sink...\n");
		OSyncFormatEnv *formatenv = osync_plugin_info_get_format_env(info);
		plgdata->gcal_format = osync_format_env_find_objformat(formatenv, "xmlformat-event-doc");
		if (!plgdata->gcal_format) {
			osync_trace(TRACE_ERROR, "%s", "Failed to find objformat xmlformat-event!");
			goto error_freeplg;
		}
		osync_objformat_ref(plgdata->gcal_format);


		osync_objtype_sink_set_connect_func(sink, gc_connect_calendar);
		osync_objtype_sink_set_disconnect_func(sink, gc_disconnect);
		osync_objtype_sink_set_get_changes_func(sink,
						gc_get_changes_calendar);
		osync_objtype_sink_set_commit_func(sink,
						gc_commit_change_calendar);
		osync_objtype_sink_set_sync_done_func(sink, gc_sync_done);


		osync_objtype_sink_set_userdata(sink, plgdata);
 		osync_objtype_sink_enable_state_db(sink, TRUE);
	}





	// Register contact sink
	sink = NULL;
	sink = osync_plugin_info_find_objtype(info, "contact");
	if( !sink ) {
		osync_trace(TRACE_ERROR, "%s", "Failed to find objtype contact!");
	}
	if( sink && osync_objtype_sink_is_enabled(sink) && plgdata->contacts ) {

		osync_trace(TRACE_INTERNAL, "\tcreating contact sink...\n");
		OSyncFormatEnv *formatenv = osync_plugin_info_get_format_env(info);
		plgdata->gcont_format = osync_format_env_find_objformat(formatenv, "xmlformat-contact-doc");
		if (!plgdata->gcont_format) {
			osync_trace(TRACE_ERROR, "%s", "Failed to find objformat xmlformat-contact!");
			goto error_freeplg;
		}
		osync_objformat_ref(plgdata->gcont_format);


		osync_objtype_sink_set_connect_func(sink, gc_connect_contact);
		osync_objtype_sink_set_disconnect_func(sink, gc_disconnect);
		osync_objtype_sink_set_get_changes_func(sink,
						gc_get_changes_contact);
		osync_objtype_sink_set_commit_func(sink,
						gc_commit_change_contact);
		osync_objtype_sink_set_sync_done_func(sink, gc_sync_done);


		osync_objtype_sink_set_userdata(sink, plgdata);
 		osync_objtype_sink_enable_state_db(sink, TRUE);
	}


	if( plgdata->calendar ) {
		plgdata->xslt_ctx_gcal = xslt_new();
		plgdata->xslt_ctx_ocal = xslt_new();
		if (!plgdata->xslt_ctx_gcal || !plgdata->xslt_ctx_ocal)
			goto error_freeplg;
		else
			osync_trace(TRACE_INTERNAL, "\tsucceed creating xslt_gcal!\n");
	}

	if( plgdata->contacts ) {
		plgdata->xslt_ctx_gcont = xslt_new();
		plgdata->xslt_ctx_ocont = xslt_new();
		if (!plgdata->xslt_ctx_gcont || !plgdata->xslt_ctx_ocont)
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

