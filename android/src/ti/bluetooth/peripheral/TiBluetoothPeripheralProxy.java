package ti.bluetooth.peripheral;

import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCallback;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothProfile;
import android.content.Context;

import org.appcelerator.kroll.KrollDict;
import org.appcelerator.kroll.KrollProxy;
import org.appcelerator.kroll.annotations.Kroll;
import org.appcelerator.titanium.TiBlob;
import org.appcelerator.kroll.common.Log;

import java.util.ArrayList;
import java.util.List;

import ti.bluetooth.TiBluetoothModule;
import ti.bluetooth.gatt.TiBluetoothCharacteristicProxy;
import ti.bluetooth.gatt.TiBluetoothServiceProxy;
import ti.bluetooth.listener.OnPeripheralConnectionStateChangedListener;

@Kroll.proxy(parentModule = TiBluetoothModule.class)
public class TiBluetoothPeripheralProxy extends KrollProxy {
  private static final String DID_DISCOVER_SERVICES = "didDiscoverServices";
  private static final String DID_DISCOVER_CHARACTERISTICS_FOR_SERVICE =
      "didDiscoverCharacteristicsForService";
  private static final String DID_UPDATE_VALUE_FOR_CHARACTERISTIC =
      "didUpdateValueForCharacteristic";
  private static final String DID_WRITE_VALUE_FOR_CHARACTERISTIC =
      "didWriteValueForCharacteristic";
  private static final String SERVICE_KEY = "service";

  private BluetoothDevice bluetoothDevice;
  private BluetoothGatt bluetoothGatt;
  private List<TiBluetoothServiceProxy> services;

  public TiBluetoothPeripheralProxy(BluetoothDevice bluetoothDevice) {
    this.bluetoothDevice = bluetoothDevice;
  }

  public void
  connectPeripheral(Context context, final boolean notifyOnConnection,
                    final boolean notifyOnDisconnection,
                    final OnPeripheralConnectionStateChangedListener
                        onPeripheralConnectionStateChangedListener) {
    bluetoothDevice.connectGatt(context, false, new BluetoothGattCallback() {
      @Override
      public void onConnectionStateChange(BluetoothGatt gatt, int status,
                                          int newState) {
        super.onConnectionStateChange(gatt, status, newState);
Log.i("[INFO] TiBluetoothModule", "onConnectionStateChange: status=>"+status+" newState=>"+newState);
Log.i("[INFO] TiBluetoothModule", "onConnectionStateChange reference: status BluetoothGatt.GATT_SUCCESS=>"+BluetoothGatt.GATT_SUCCESS+" newstatus BluetoothProfile.STATE_CONNECTED=>"+BluetoothProfile.STATE_CONNECTED+" BluetoothProfile.STATE_DISCONNECTED=>"+BluetoothProfile.STATE_DISCONNECTED);

        if (status == BluetoothGatt.GATT_SUCCESS) {
          if (newState == BluetoothProfile.STATE_CONNECTED) {
            bluetoothGatt = gatt;
            if (notifyOnConnection) {
              onPeripheralConnectionStateChangedListener
                  .onPeripheralConnectionStateConnected(
                      TiBluetoothPeripheralProxy.this);
            }
          } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
            if (notifyOnDisconnection) {
              onPeripheralConnectionStateChangedListener
                  .onPeripheralConnectionStateDisconnected(
                      TiBluetoothPeripheralProxy.this);
            }
          }
        } else if (status == 133 && newState == BluetoothProfile.STATE_DISCONNECTED) {
          Log.i("[INFO] TiBluetoothModule", "error 133 - you should retry connection");
          onPeripheralConnectionStateChangedListener
                .onPeripheralConnectionStateError133(
                    TiBluetoothPeripheralProxy.this);

        } else {
          onPeripheralConnectionStateChangedListener
              .onPeripheralConnectionStateError(
                  TiBluetoothPeripheralProxy.this);
        
        }
      }

      @Override
      public void onServicesDiscovered(BluetoothGatt gatt, int status) {
        super.onServicesDiscovered(gatt, status);

        services = mapServices(gatt.getServices());
        bluetoothGatt = gatt;

        firePeripheralEvent(DID_DISCOVER_SERVICES,
                            TiBluetoothPeripheralProxy.this, null, null);
      }

      @Override
      public void onCharacteristicWrite(
          BluetoothGatt gatt, BluetoothGattCharacteristic characteristic,
          int status) {
        super.onCharacteristicWrite(gatt, characteristic, status);

        firePeripheralEvent(DID_WRITE_VALUE_FOR_CHARACTERISTIC,
                            TiBluetoothPeripheralProxy.this, null,
                            new TiBluetoothCharacteristicProxy(characteristic));
      }

      @Override
      public void onCharacteristicChanged(
          BluetoothGatt gatt,
          final BluetoothGattCharacteristic characteristic) {
        super.onCharacteristicChanged(gatt, characteristic);

        firePeripheralEvent(DID_UPDATE_VALUE_FOR_CHARACTERISTIC,
                            TiBluetoothPeripheralProxy.this, null,
                            new TiBluetoothCharacteristicProxy(characteristic));
      }
    });
  }

  public void disconnectPeripheral() {
    try {
      if (bluetoothGatt != null){
        bluetoothGatt.disconnect();
      }
    } catch( Exception e) {
      Log.e("TiBluetoothPeripheralProxy disconnect", e.getMessage());
    }
    try {
      if (bluetoothGatt != null){
        bluetoothGatt.close();
      }
    } catch( Exception e) {
      Log.e("TiBluetoothPeripheralProxy close", e.getMessage());
    }      
  }

  private List<TiBluetoothServiceProxy>
  mapServices(List<BluetoothGattService> services) {
    List<TiBluetoothServiceProxy> tiBluetoothServiceProxies = new ArrayList<>();

    for (BluetoothGattService bluetoothGatt : services) {
      tiBluetoothServiceProxies.add(new TiBluetoothServiceProxy(bluetoothGatt));
    }

    return tiBluetoothServiceProxies;
  }

  private void
  firePeripheralEvent(String event,
                      TiBluetoothPeripheralProxy bluetoothPeripheral,
                      TiBluetoothServiceProxy service,
                      TiBluetoothCharacteristicProxy characteristic) {
    KrollDict kd = new KrollDict();
    kd.put("peripheral", bluetoothPeripheral);
    kd.put("service", service);
    kd.put("characteristic", characteristic);

    fireEvent(event, kd);
  }

  @Kroll.method
  public void discoverServices() {
    bluetoothGatt.discoverServices();
  }

  @Kroll.method
  public void discoverCharacteristicsForService(KrollDict args) {
    TiBluetoothServiceProxy service =
        (TiBluetoothServiceProxy)args.get(SERVICE_KEY);

    if (service.getCharacteristics().length > 0) {
      firePeripheralEvent(DID_DISCOVER_CHARACTERISTICS_FOR_SERVICE, this,
                          service, null);
    }
  }

  @Kroll
      .getProperty
      @Kroll.method
      public String getName() {
    return bluetoothDevice.getName();
  }

  @Kroll
      .getProperty
      @Kroll.method
      public String getAddress() {
    return bluetoothDevice.getAddress();
  }

  @Kroll
      .getProperty
      @Kroll.method
      public Object[] getServices() {
    return services.toArray();
  }

  @Kroll.method
  public void setNotifyValueForCharacteristic(
      boolean enabled, TiBluetoothCharacteristicProxy characteristic) {

    Log.i("[INFO] TiBluetoothModule", "setNotifyValueForCharacteristic enabled: " + enabled);
    bluetoothGatt.setCharacteristicNotification(
        characteristic.getCharacteristic(), enabled);
  }

  @Kroll.method
  public void writeValueForCharacteristicWithType(
      String value,
      TiBluetoothCharacteristicProxy tiBluetoothCharacteristicProxy,
      int writeType) {
    BluetoothGattCharacteristic characteristic =
        tiBluetoothCharacteristicProxy.getCharacteristic();

    characteristic.setWriteType(BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT);
    Log.i("[INFO] TiBluetoothModule", "value: " + value);
    byte[] newData = hexToByteData(value);
    Boolean result = characteristic.setValue(newData);
    Log.i("[INFO] TiBluetoothModule", "could write locally: " +result);
    bluetoothGatt.writeCharacteristic(characteristic);
  }

  public byte[] hexToByteData(String hex)
  {
      byte[] convertedByteArray = new byte[hex.length()/2];
      int count  = 0;

      for( int i = 0; i < hex.length() -1; i += 2 )
      {
          String output;
          output = hex.substring(i, (i + 2));
          int decimal = Integer.parseInt(output, 16);
          convertedByteArray[count] =  (byte)(decimal & 0xFF);
          count ++;
      }
      return convertedByteArray;
  }
}
