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
 * - find a way to report changes to opensync and make it work
 * - review code for leaks (I'm not sure if I'm using opensync API correctly...)
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
	struct xslt_resources *xslt_ctx_gcal;
	struct xslt_resources *xslt_ctx_gcont;
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

	if ((plgdata->calendar) && (counter == 0)) {
		result = gcal_get_authentication(plgdata->calendar, plgdata->username,
						 plgdata->password);
		++counter;
		if (result == -1)
			goto error;

		snprintf(buffer, sizeof(buffer) - 1, "%s/gcal2osync.xslt",
			 plgdata->xslt_path);
		if ((result = xslt_initialize(plgdata->xslt_ctx_gcal, buffer)))
			goto error;
		osync_trace(TRACE_INTERNAL, "\ndone calendar: %s\n", buffer);
	}

	if (((plgdata->contacts) && (counter == 1)) ||
	    ((plgdata->gcont_sink) && (!plgdata->gcal_sink))) {
		result = gcal_get_authentication(plgdata->contacts, plgdata->username,
						 plgdata->password);
		counter++;
		if (result == -1)
			goto error;

		snprintf(buffer, sizeof(buffer) - 1, "%s/gcont2osync.xslt",
			 plgdata->xslt_path);
		if ((result = xslt_initialize(plgdata->xslt_ctx_gcont, buffer)))
			goto error;
		osync_trace(TRACE_INTERNAL, "\ndone contact: %s\n", buffer);
	}

	osync_context_report_success(ctx);
	osync_trace(TRACE_EXIT, "%s", __func__);
	return;

error:
	osync_trace(TRACE_INTERNAL, "Failed to load xslt stylesheet!\n");
	osync_error_set(&error, OSYNC_ERROR_GENERIC,
			"Unable load xslt stylesheet data.");
	osync_context_report_osyncerror(ctx, &error);
}

static void gc_get_changes_calendar(OSyncObjTypeSink *sink,
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
	gcal_event event;
	OSyncError *anchor_error = NULL;

	if (!(osync_objtype_sink_get_anchor(plgdata->gcal_sink)))
		goto error;

	timestamp = osync_anchor_retrieve(osync_objtype_sink_get_anchor(plgdata->gcal_sink),
					  &anchor_error);
	if (!timestamp) {
		msg = "gcalendar: Anchor returned is NULL!";
		goto error;
	}

	if (strlen(timestamp) > 0)
		osync_trace(TRACE_INTERNAL, "timestamp is: %s\n", timestamp);
	else
		osync_trace(TRACE_INTERNAL, "first sync!\n");

	if (osync_objtype_sink_get_slowsync(plgdata->gcal_sink)) {
		osync_trace(TRACE_INTERNAL, "\n\t\tgcal: Client asked for slow syncing...\n");
		slow_sync_flag = 1;
		result = gcal_get_events(plgdata->calendar, &(plgdata->all_events));

	} else {
		osync_trace(TRACE_INTERNAL, "\n\t\tgcal: Client asked for fast syncing...\n");
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
		goto no_changes;
	} else
		osync_trace(TRACE_INTERNAL, "gcalendar: changes count: %d\n",
			    plgdata->all_events.length);


	// Calendar returns most recently updated event as first element
	event = gcal_event_element(&(plgdata->all_events), 0);
	if (!event) {
		msg = "Cannot access last updated event!\n";
		goto error;
	}
	plgdata->cont_timestamp = strdup(gcal_event_get_updated(event));
	if (!plgdata->cont_timestamp) {
		msg = "Failed copying event timestamp!\n";
		goto error;
	}

	for (i = 0; i < plgdata->all_events.length; ++i) {
		event = gcal_event_element(&(plgdata->all_events), i);
		if (!event)
			goto error;

		osync_trace(TRACE_INTERNAL, "gevent: timestamp:%s\tevent:%s\n",
			    timestamp, gcal_event_get_updated(event));
		// Workaround for inclusive returned results
		if ((timestamp_cmp(timestamp, gcal_event_get_updated(event)) == 0)
		    && !slow_sync_flag
		    && !gcal_event_is_deleted(event)) {
			osync_trace(TRACE_INTERNAL, "gevent: old event.");
			continue;
		} else
			osync_trace(TRACE_INTERNAL, "gevent: new or deleted event!");

		raw_xml = gcal_event_get_xml(event);
		if ((result = xslt_transform(plgdata->xslt_ctx_gcal,
					     raw_xml)))
			goto error;

		raw_xml = (char*) plgdata->xslt_ctx_gcal->xml_str;
		odata = osync_data_new(strdup(raw_xml),
				       strlen(raw_xml),
				       plgdata->gcal_format, &error);
		if (!odata)
			goto cleanup;

		if (!(chg = osync_change_new(&error)))
			goto cleanup;
		osync_data_set_objtype(odata, osync_objtype_sink_get_name(sink));
		osync_change_set_data(chg, odata);
		osync_data_unref(odata);

		osync_change_set_uid(chg, gcal_event_get_url(event));

		if (slow_sync_flag)
			osync_change_set_changetype(chg, OSYNC_CHANGE_TYPE_ADDED);
		else
			if (gcal_event_is_deleted(event)) {
				osync_change_set_changetype(chg, OSYNC_CHANGE_TYPE_DELETED);
				osync_trace(TRACE_INTERNAL, "deleted entry!");
			}
			else
				osync_change_set_changetype(chg, OSYNC_CHANGE_TYPE_MODIFIED);

		osync_context_report_change(ctx, chg);
		osync_change_unref(chg);
	}

no_changes:

	// Load XSLT style to convert osync xmlformat-event --> gdata
	snprintf(buffer, sizeof(buffer) - 1, "%s/osync2gcal.xslt",
		 plgdata->xslt_path);
	if ((result = xslt_initialize(plgdata->xslt_ctx_gcal, buffer))) {
		msg = "Cannot initialize new XSLT!\n";
		goto error;
	}

	osync_trace(TRACE_INTERNAL, "\ndone calendar: %s\n", buffer);

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


static void gc_get_changes_contact(OSyncObjTypeSink *sink,
			OSyncPluginInfo *info, OSyncContext *ctx,
			osync_bool slow_sync, void *data)
{
	osync_trace(TRACE_ENTRY, "%s(%p, %p, %p)", __func__, data, info, ctx);
	char buffer[512];
	static int counter = 0;
	struct gc_plgdata *plgdata = data;
	char slow_sync_flag = 0;
	OSyncError *error = NULL;
	OSyncData *odata = NULL;
	OSyncChange *chg = NULL;
	int result = 0, i;
	char *timestamp = NULL, *msg, *raw_xml = NULL;
	gcal_contact contact;
	OSyncError *anchor_error = NULL;


	if (!(osync_objtype_sink_get_anchor(sink)))
		goto error;

	timestamp = osync_sink_state_get(osync_objtype_sink_get_anchor(sink),
					  &anchor_error);
	if (!timestamp) {
		msg = "gcontact: Anchor returned is NULL!";
		goto error;
	}

	if (strlen(timestamp) > 0)
		osync_trace(TRACE_INTERNAL, "timestamp is: %s\n", timestamp);
	else
		osync_trace(TRACE_INTERNAL, "first sync!\n");

	if (osync_objtype_sink_get_slowsync(sink)) {
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

		raw_xml = plgdata->xslt_ctx_gcont->xml_str;
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

		osync_change_set_uid(chg, gcal_contact_get_url(contact));

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
	snprintf(buffer, sizeof(buffer) - 1, "%s/osync2gcont.xslt",
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
	//OSyncObjTypeSink *sink = osync_plugin_info_get_sink(info);
	struct gc_plgdata *plgdata = data;
	gcal_event event = NULL;
	int size, result;
	char *osync_xml = NULL, *msg = NULL, *raw_xml = NULL, *updated_event = NULL;
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
	if ((result = xslt_transform(plgdata->xslt_ctx_gcal, osync_xml))) {
		msg = "Failed converting from osync xmlevent to gcalendar\n";
		goto error;
	}
	raw_xml = plgdata->xslt_ctx_gcal->xml_str;

	osync_trace(TRACE_EXIT, "osync: %s\ngcont: %s\n\n", osync_xml, raw_xml);

	switch (osync_change_get_changetype(change)) {
		case OSYNC_CHANGE_TYPE_ADDED:
			result = gcal_add_xmlentry(plgdata->calendar, raw_xml, &updated_event);
			if (result == -1) {
				msg = "Failed adding new event!\n";
				result = gcal_status_httpcode(plgdata->calendar);
				goto error;
			}

			if (!(event = gcal_event_new(updated_event))) {
				msg = "Failed recovering updated fields!\n";
				goto error;
			}
		break;

		case OSYNC_CHANGE_TYPE_MODIFIED:
			result = gcal_update_xmlentry(plgdata->calendar, raw_xml, &updated_event,
						      NULL);
			if (result == -1) {
				msg = "Failed editing event!\n";
				goto error;
			}

			if (!(event = gcal_event_new(updated_event))) {
				msg = "Failed recovering updated fields!\n";
				goto error;
			}
		break;

		case OSYNC_CHANGE_TYPE_DELETED:
			result = gcal_erase_xmlentry(plgdata->calendar, raw_xml);
			if (result == -1) {
				msg = "Failed deleting event!\n";
				goto error;
			}
		break;

		default:
			osync_context_report_error(ctx, OSYNC_ERROR_NOT_SUPPORTED,
						   "Unknown change type");
			goto error;
		break;
	}

	if (updated_event)
		free(updated_event);

	if (event) {
		// update the timestamp
		if (plgdata->cal_timestamp)
			free(plgdata->cal_timestamp);
		plgdata->cal_timestamp = strdup(gcal_event_get_updated(event));
		if (!plgdata->cal_timestamp) {
			msg = "Failed copying contact timestamp!\n";
			goto error;
		}

		// FIXME: not sure if this works
		// Inform the new ID
		osync_change_set_uid(change, gcal_event_get_url(event));
		gcal_event_delete(event);

	}

	//	free(osync_xml);

	osync_context_report_success(ctx);
	osync_trace(TRACE_EXIT, "%s", __func__);

	return;
error:
	if (updated_event)
		free(updated_event);

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
	gcal_contact contact = NULL;
	int size, result;
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
	raw_xml = plgdata->xslt_ctx_gcont->xml_str;

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
			result = gcal_update_xmlentry(plgdata->contacts, raw_xml, &updated_contact,
						      NULL);
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

	osync_context_report_error(ctx, OSYNC_ERROR_GENERIC, msg);
	osync_trace(TRACE_EXIT, "%s:%sHTTP code: %d", __func__, msg, result);
}

static void gc_sync_done(OSyncObjTypeSink *sink, OSyncPluginInfo *info,
			OSyncContext *ctx, void *data)
{
	osync_trace(TRACE_ENTRY, "%s(%p, %p, %p)", __func__, data, info, ctx);
	struct gc_plgdata *plgdata = data;
	OSyncError *anchor_error;

	if (plgdata->calendar && plgdata->cal_timestamp) {
		osync_trace(TRACE_INTERNAL, "query updated timestamp: %s\n",
				    plgdata->cal_timestamp);
		osync_anchor_update(osync_objtype_sink_get_anchor(plgdata->gcal_sink),
				    plgdata->cal_timestamp, &anchor_error);
	}

	if (plgdata->contacts && plgdata->cont_timestamp) {
		osync_trace(TRACE_INTERNAL, "query updated timestamp: %s\n",
				    plgdata->cont_timestamp);
		osync_anchor_update(osync_objtype_sink_get_anchor(plgdata->gcont_sink),
				    plgdata->cont_timestamp, &anchor_error);
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
	OSyncPluginAuthentication *auth;
	OSyncPluginAdvancedOption *advanced;
	OSyncList *resources;
	OSyncList *r;
	const char *objtype, *tmp;
	int i, numobjs;

	//osync_error_set(error, OSYNC_ERROR_GENERIC, "no msg");
	plgdata = osync_try_malloc0(sizeof(struct gc_plgdata), error);
	config = osync_plugin_info_get_config(info);
	if ((!plgdata) || (!config)) {
		osync_error_set(error, OSYNC_ERROR_GENERIC,
				"Unable to get config data.");
		goto error_freeplg;
	}

	advanced = osync_plugin_config_get_advancedoption_value_by_name(config, "xslt");
	if (!advanced) {
		osync_trace(TRACE_INTERNAL, "Cannot locate xslt config!\n");
		goto error_freeplg;
	}

	if (!(plgdata->xslt_path = strdup(osync_plugin_advancedoption_get_value(advanced))))
		goto error_freeplg;

	resources = osync_plugin_config_get_resources(config);
	numobjs = osync_plugin_info_num_objtypes(info);

	for (i = 1, r = resources; r; r = r->next, i++) {
		osync_trace(TRACE_INTERNAL, "field: %s\n", osync_plugin_resource_get_objtype(r->data));
		if (!(strcmp(osync_plugin_resource_get_objtype(r->data), "event")))
			if (!(plgdata->calendar = gcal_new(GCALENDAR)))
				goto error_freeplg;
			else {
				osync_trace(TRACE_INTERNAL, "\tcreated calendar obj!\n");
				gcal_set_store_xml(plgdata->calendar, 1);
			}

		if (!(strcmp(osync_plugin_resource_get_objtype(r->data), "contact")))
			if (!(plgdata->contacts = gcal_new(GCONTACT)))
				goto error_freeplg;
			else {
				osync_trace(TRACE_INTERNAL, "\tcreated contact obj!\n");
				gcal_set_store_xml(plgdata->contacts, 1);
			}

	}


	// TODO: how works resource policy? For while, copy everything...
	for (i = 0; i < numobjs; i++) {

		if (!plgdata->username) {
			auth = osync_plugin_config_get_authentication(config);
			tmp = osync_plugin_authentication_get_username(auth);
			if (!tmp)
				goto error_freeplg;
			else
				if (!(plgdata->username = strdup(tmp)))
					goto error_freeplg;

		}

		if (!plgdata->password) {
			tmp = osync_plugin_authentication_get_password(auth);
			if (!tmp)
				goto error_freeplg;
			else
				if (!(plgdata->password = strdup(tmp)))
					goto error_freeplg;

		}
		// TODO: get proxy/calendar title/resources/etc

	}

	OSyncObjTypeSinkFunctions functions_gcal;
	memset(&functions_gcal, 0, sizeof(functions_gcal));
	functions_gcal.connect = gc_connect;
	functions_gcal.get_changes = gc_get_changes_calendar;
	functions_gcal.commit = gc_commit_change_calendar;
	functions_gcal.disconnect = gc_disconnect;
	functions_gcal.sync_done = gc_sync_done;


	if (plgdata->calendar) {
		osync_trace(TRACE_INTERNAL, "\tcreating calendar sink...\n");
		OSyncFormatEnv *formatenv1 = osync_plugin_info_get_format_env(info);
		plgdata->gcal_format = osync_format_env_find_objformat(formatenv1, "xmlformat-event-doc");
		if (!plgdata->gcal_format) {
			osync_trace(TRACE_ERROR, "%s", "Failed to find objformat xmlformat-event!");
			goto error_freeplg;
		}
		osync_objformat_ref(plgdata->gcal_format);

		plgdata->gcal_sink = osync_plugin_info_find_objtype(info, "event");
		if (!plgdata->gcal_sink) {
			osync_trace(TRACE_ERROR, "%s", "Failed to find objtype event!");
			goto error_freeplg;
		}

		osync_objtype_sink_set_functions(plgdata->gcal_sink, functions_gcal, plgdata);
		osync_plugin_info_add_objtype(info, plgdata->gcal_sink);

 		osync_objtype_sink_enable_anchor(plgdata->gcal_sink, TRUE);
	}

	OSyncObjTypeSinkFunctions functions_gcont;
	memset(&functions_gcont, 0, sizeof(functions_gcont));
	functions_gcont.connect = gc_connect;
	functions_gcont.get_changes = gc_get_changes_contact;
	functions_gcont.commit = gc_commit_change_contact;
	functions_gcont.disconnect = gc_disconnect;
	functions_gcont.sync_done = gc_sync_done;

	if (plgdata->contacts) {
		osync_trace(TRACE_INTERNAL, "\tcreating contact sink...\n");
		OSyncFormatEnv *formatenv2 = osync_plugin_info_get_format_env(info);
		plgdata->gcont_format = osync_format_env_find_objformat(formatenv2, "xmlformat-contact-doc");
		if (!plgdata->gcont_format) {
			osync_trace(TRACE_ERROR, "%s", "Failed to find objformat xmlformat-contact!");
			goto error_freeplg;
		}
		osync_objformat_ref(plgdata->gcont_format);

		plgdata->gcont_sink = osync_plugin_info_find_objtype(info, "contact");
		if (!plgdata->gcont_sink) {
			osync_trace(TRACE_ERROR, "%s", "Failed to find objtype contact!");
			goto error_freeplg;
		}

		osync_objtype_sink_set_functions(plgdata->gcont_sink, functions_gcont, plgdata);
		osync_objtype_sink_enable_anchor(plgdata->gcont_sink, TRUE);
		osync_plugin_info_add_objtype(info, plgdata->gcont_sink);

	}

	if (plgdata->calendar)
		if (!(plgdata->xslt_ctx_gcal = xslt_new()))
			goto error_freeplg;
		else
			osync_trace(TRACE_INTERNAL, "\tsucceed creating xslt_gcal!\n");

	if (plgdata->contacts)
		if (!(plgdata->xslt_ctx_gcont = xslt_new()))
			goto error_freeplg;
		else
			osync_trace(TRACE_INTERNAL, "\tsucceed creating xslt_gcont!\n");

	osync_trace(TRACE_EXIT, "%s", __func__);

	return plgdata;

error_freeplg:
	if (plgdata)
		free_plg(plgdata);
out:
	osync_trace(TRACE_EXIT_ERROR, "%s: %s", __func__, osync_error_print(error));
	return NULL;
}

static osync_bool gc_discover(OSyncPluginInfo *info, void *data, OSyncError **error)
{
	osync_trace(TRACE_ENTRY, "%s(%p, %p, %p)", __func__, data, info, error);

	struct gc_plgdata *plgdata = data;

	if (plgdata->calendar)
		osync_objtype_sink_set_available(plgdata->gcal_sink, TRUE);
	if (plgdata->contacts)
		osync_objtype_sink_set_available(plgdata->gcont_sink, TRUE);

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
	if (!plugin)
		goto error;

	osync_plugin_set_name(plugin, "google-data");
	osync_plugin_set_longname(plugin, "Google calendar/plugin");
	osync_plugin_set_description(plugin, "Google calendar and contacts plugin");

	osync_plugin_set_initialize(plugin, gc_initialize);
	osync_plugin_set_finalize(plugin, gc_finalize);
	osync_plugin_set_discover(plugin, gc_discover);

	osync_plugin_env_register_plugin(env, plugin);
	osync_plugin_unref(plugin);

	osync_trace(TRACE_EXIT, "%s", __func__);
	return TRUE;

error:
	osync_trace(TRACE_EXIT_ERROR, "Unable to register: %s", osync_error_print(error));
	osync_error_unref(error);
	return FALSE;
}

int get_version(void)
{
	return 1;
}

