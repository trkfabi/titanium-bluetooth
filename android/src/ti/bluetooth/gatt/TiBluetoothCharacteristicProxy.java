package ti.bluetooth.gatt;

import android.bluetooth.BluetoothGattCharacteristic;
import org.appcelerator.kroll.KrollProxy;
import org.appcelerator.kroll.annotations.Kroll;
import org.appcelerator.titanium.TiBlob;
import ti.bluetooth.TiBluetoothModule;
import org.appcelerator.kroll.common.Log;

@Kroll.proxy(parentModule = TiBluetoothModule.class)
public class TiBluetoothCharacteristicProxy extends KrollProxy {
  private BluetoothGattCharacteristic characteristic;

  public TiBluetoothCharacteristicProxy(
      BluetoothGattCharacteristic characteristic) {
    this.characteristic = characteristic;
  }

  public static String ByteArrayToHexString(byte[] bytes) {
      final char[] hexArray = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
      char[] hexChars = new char[bytes.length * 2]; // Each byte has two hex characters (nibbles)
      int v;
      for (int j = 0; j < bytes.length; j++) {
          v = bytes[j] & 0xFF; // Cast bytes[j] to int, treating as unsigned value
          hexChars[j * 2] = hexArray[v >>> 4]; // Select hex character from upper nibble
          hexChars[j * 2 + 1] = hexArray[v & 0x0F]; // Select hex character from lower nibble
      }
      return new String(hexChars);
  }

  @Kroll.getProperty
  public String getUuid() {
    return characteristic.getUuid().toString().toUpperCase();
  }

  @Kroll.getProperty
  public String getValue() {
      if (characteristic == null){
          return null;
      } else {
          if (characteristic.getValue() == null){
              return null;
          } else {
              return ByteArrayToHexString(characteristic.getValue()); //TiBlob.blobFromData(characteristic.getValue());
          }
    }
  }

  @Kroll.getProperty
  public int getCharacteristicProperties() {
    return characteristic.getProperties();
  }

  @Kroll.getProperty
  public int getPermissions() {
    return characteristic.getPermissions();
  }

  public BluetoothGattCharacteristic getCharacteristic() {
    return characteristic;
  }
}
