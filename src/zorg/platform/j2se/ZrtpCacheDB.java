/**
 * ZRTP.org is a ZRTP protocol implementation  
 * Copyright (C) 2012 - PrivateWave Italia S.p.A.
 * 
 * This  program  is free software:  you can  redistribute it and/or
 * modify  it  under  the terms  of  the  GNU Affero  General Public
 * License  as  published  by the  Free Software Foundation,  either 
 * version 3 of the License,  or (at your option) any later version.
 * 
 * This program is  distributed in  the hope that it will be useful,
 * but WITHOUT ANY WARRANTY;  without even  the implied  warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU 
 * Affero General Public License for more details.
 * 
 * You should have received a copy of the  GNU Affero General Public
 * License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 * 
 * For more information, please contact PrivateWave Italia S.p.A. at
 * address zorg@privatewave.com or http://www.privatewave.com 
 */
package zorg.platform.android;

import java.util.Enumeration;
import java.util.Vector;

import zorg.ZrtpCacheEntry;
import zorg.platform.PersistentHashtable;
import zorg.platform.ZrtpLogger;
import android.app.Application;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.database.sqlite.SQLiteStatement;

public class ZrtpCacheDB implements PersistentHashtable {
	
	private static final String DATABASE_NAME = "zrtp_cache.db";
	private static final int 	DATABASE_VERSION = 1;

	private static final String TABLE_NAME = "zrtp_cache";
	private static final String COLUMN_ZID = "zid";
	private static final String COLUMN_DATA = "data";
	private static final String COLUMN_NUMBER = "number";

	public static final String DATABASE_CREATE = "create table " + TABLE_NAME
			+ " (_id integer primary key autoincrement," + COLUMN_ZID
			+ " text not null," + COLUMN_DATA + " blob not null,"
			+ COLUMN_NUMBER + " text not null);";
	
	private SQLiteStatement insertStmt;
	
	private static final String INSERT = "insert into " + TABLE_NAME + "("
			+ COLUMN_ZID + "," + COLUMN_DATA + "," + COLUMN_NUMBER
			+ ") values (?,?,?);";

	private SQLiteDatabase database;
	
	private ZrtpLogger logger;
	
	public ZrtpCacheDB(Application acc, ZrtpLogger l) {
		logger = l;
		
		OpenHelper openHelper = new OpenHelper(
				acc.getApplicationContext(), logger);
		this.database = openHelper.getWritableDatabase();
		this.insertStmt = this.database.compileStatement(INSERT);
	}

	@Override
	public ZrtpCacheEntry get(String zid) {
		ZrtpCacheEntry entry = null;
		
		String zidDbFormat = convertToDBFormat(zid);

		String[] zidColumn = new String[] { COLUMN_ZID,
				COLUMN_DATA,
				COLUMN_NUMBER};

		Cursor cursor = this.database.query(TABLE_NAME, zidColumn, COLUMN_ZID + "='" + zidDbFormat + "'", null,
				null, null, null);
		
		logger.log("[Zrtp Cache] Found " + cursor.getCount() + " entry in zrtp_cache_db for zid " + zidDbFormat);

		if (cursor.moveToFirst()) {
			do {
				entry = new AndroidCacheEntry(convertFromDBFormat(cursor.getString(0)),
						cursor.getBlob(1),
						cursor.getString(2));
			} while (cursor.moveToNext());
		}
		if (cursor != null && !cursor.isClosed()) {
			cursor.close();
		}
		
		if (entry != null) {
			logger.log("[Zrtp Cache] Entry for "  + zidDbFormat + " and number " + entry.getNumber() + " found!");
		} else
			logger.log("[Zrtp Cache] No entry found!");
		
		return entry;
	}

	@Override
	public Enumeration<String> keys() {
		Vector<String> list = new Vector<String>();

		String[] zidColumn = new String[] { COLUMN_ZID};

		Cursor cursor = this.database.query(TABLE_NAME, zidColumn, null, null,
				null, null, null);

		if (cursor.moveToFirst()) {
			do {
				list.add(convertFromDBFormat(cursor.getString(0)));
			} while (cursor.moveToNext());
		}
		if (cursor != null && !cursor.isClosed()) {
			cursor.close();
		}
		
		logger.log("[Zrtp Cache] Found " + list.size() + " keys in zrtp_cache_db");
		return list.elements();
	}

	@Override
	public void put(String zid, byte[] data, String phoneNumber) {
		/* first, search for a data to update */
		ZrtpCacheEntry oldEntry = get(zid);
		String zidDbFormat = convertToDBFormat(zid);
		
		if (oldEntry != null) {
			logger.log("[Zrtp Cache] An old data found...update it!");
			/* UPDATE DATA */

			ContentValues newData = new ContentValues();
			newData.put(COLUMN_ZID, zidDbFormat);
			newData.put(COLUMN_DATA, data);
			newData.put(COLUMN_NUMBER, phoneNumber == null ? oldEntry.getNumber() : phoneNumber);

			database.update(TABLE_NAME, newData, COLUMN_ZID +"='"+zidDbFormat + "'", null);
		} else {
			logger.log("[Zrtp Cache] Insert new data!");
			/* INSERT DATA */
			this.insertStmt.bindString(1, zidDbFormat);
			this.insertStmt.bindBlob(2,data);
			this.insertStmt.bindString(3, phoneNumber == null ? "" : phoneNumber);

			this.insertStmt.executeInsert();
		}
		
	}

	@Override
	public void remove(String zid) {
		String zidDbFormat = convertToDBFormat(zid);
		this.database.delete(TABLE_NAME, COLUMN_ZID + "='" + zidDbFormat + "'", null);
		logger.log("[Zrtp Cache] deleted element for zid " + zidDbFormat);
	}

	@Override
	public void reset() {
		this.database.delete(TABLE_NAME, null, null);
		logger.log("[Zrtp Cache] Reset zrtp_cache_db");
	}
	
	private String convertFromDBFormat(String original) {
		byte[] buffer = new byte[original.length() / 2];
		for (int i = 0; i < buffer.length; i++) {
			buffer[i] = (byte) Short.parseShort(
					original.substring(i * 2, i * 2 + 2), 16);
		}

		return new String(buffer);

	}
	
	private String convertToDBFormat(String original) {
		return AndroidPlatform.getInstance().getUtils().byteToHexString(original.getBytes());
	}

	private static class OpenHelper extends SQLiteOpenHelper {
		ZrtpLogger logger;
		
		
		OpenHelper(Context context, ZrtpLogger logger) {
			super(context, DATABASE_NAME, null, DATABASE_VERSION);
			this.logger = logger;
		}

		@Override
		public void onCreate(SQLiteDatabase db) {
			try {
				db.execSQL(DATABASE_CREATE);
			} catch (Exception e) {
				logger.logException(e.getMessage());
			}
		}

		@Override
		public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
			db.execSQL("DROP TABLE IF EXISTS " + TABLE_NAME);
			onCreate(db);
		}
	}

}
