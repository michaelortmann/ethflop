�EFLOPMOJMIRMILENA                     X                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  	�t.�� �.8&� u��$u��1����PSQRVW�� �� ��  � ��� ���t��*�_��؈���P��$����� ��  XrL� �<�8�t8�u>8� u�� �� 86� u��8� tֈ6� ��� � ���� ���;*t��_^ZY[X���.�.� .�.� .:� u�.:� u�U��f�].�� .�&� ����.�� .�� .�� .�� �tk��u.�&� �_��t��tr���rP�;%� tI.�&� .:� t*���s.�� �2.�!�uVWQ�} ��� Y_^��.� .�".�$.�&�.�&� .�� .�&� �tU��N]�%� t�.�&� .:� t�VWQ�' ���Y_^�b�s.�� �.�!�u�.�� ��P.�� � ��Y�P� �߾*X��� �� �0�	 �� �R� �� �d�1Ɋ� �� v�6	�u�/�� �<uu�<a��  tY<b�� tP<su�#<it<rt<et<nt<lt<dt< �����Ls���&� L���!�	���!�L�!� U��N]��"s�� �� �� s�	�x�!�L�!�� �� �ns�	���!�L�!��� �� � ���� �� ���� ���� ���  �& �"�s��	��!�L�!�	�*�!�	�-�!�*�� �,�� �.�� �0�� ��� ��� ��� ������/.�� .�� ����/�%��!.�, �I�!�	���!� 1�} �!�_��<�w&�5�!&�PKu�&�T u�&�DRu�&�	VRu����ø5�!������ ���������s� �%&�� &�� �!�&�� &�� R�/Z�/� �I�!s�	�0�!�	�[�!� L�!�&�� ��&�� �PSQRVW����� �� � �,���� �� _^ZY[Xô	�W�!�L�!�	���!�L�!�H�r�	���!�&�� ��A�!��:�!�	�-�!� � L�!� 1�&��� ��� CC��&�� �� &�� �� �� ���e�s�	���!�L�!����� �� 1ۋ�� ��*CC���1���$��s	�	��!�ô	�*�!� &�� �"&�� �$&�� �&&�� ��ethflop v0.6 - a floppy drive emulator over Ethernet
Copyright (C) 2019 Mateusz Viste

=== USAGE ====================================================================
ethflop a           installs the ethflop TSR as A:
ethflop b           installs ethflop as B: (works only if you have a real B:)
ethflop i DISKNAME  'inserts' the virtual floppy named 'DISKNAME'
ethflop ip DSKNAME  same as 'i', but the inserted floppy is WRITE PROTECTED
ethflop r OLD NEW   renames virt. floppy 'OLD' to 'NEW'
ethflop e           'ejects' currently loaded virtual floppy
ethflop nSZ DSKNAME creates a new virt. floppy DSKNAME, SZ KB big. SZ can be:
                    360, 720, 1200, 1440, 2880, 4800, 8100, 9600, 15500, 31000
ethflop l           displays the list of available virt. floppies
ethflop d DISKNAME  DELETES virt. floppy named DISKNAME - BE CAREFUL!
ethflop s           displays current status of the ethflop TSR
ethflop u           unloads the ethflop TSR

=== NOTES ====================================================================
 * Disk names must be 1 to 8 characters long. Only A-Z, 0-9 and '_-' allowed.
 * ethflop requires the presence of an ethflop server on the local network.

=== LICENSE ==================================================================
ethflop is published under the terms of the ISC license. See ETHFLOP.TXT.
 $ethflop has been installed$ERROR: ethflop is already installed$ERROR: ethflop is not installed or has been overloaded by another ISR$ERROR: Failed to free TSR's memory segment$ethflop has been uninstalled$ERROR: no packet driver found$ethflop is currently installed as drive $ERROR: packet driver initialization failed$NOTE: no INT 2Fh,AH=13h support detected$ERROR: server unreachable$
$MONIKA      ��                  XP��
1ۭ��1���X�1ێ�&�l�