import { Button, ButtonIcon, View } from '@nuri/rn';

type Props = {
  onDigit: (digit: string) => void;
  onDelete: () => void;
  deleteAccessibilityLabel: string;
};

/**
 * The numeric keypad composition from the official Nuri RN AmountSheet demo.
 * Every rendered primitive and every spacing/size value comes from @nuri/rn.
 */
export function NumericKeypad({ onDigit, onDelete, deleteAccessibilityLabel }: Props) {
  return (
    <View direction="column" gap="sm">
      {[
        ['1', '2', '3'],
        ['4', '5', '6'],
        ['7', '8', '9'],
      ].map((row) => (
        <View key={row.join('')} direction="row" gap="sm">
          {row.map((digit) => (
            <View key={digit} fill="even">
              <Button size="lg" onPress={() => onDigit(digit)}>{digit}</Button>
            </View>
          ))}
        </View>
      ))}
      <View direction="row" gap="sm">
        <View fill="even">
          <Button size="lg" disabled accessibilityLabel="Empty keypad key" />
        </View>
        <View fill="even">
          <Button size="lg" onPress={() => onDigit('0')}>0</Button>
        </View>
        <View fill="even">
          <Button size="lg" onPress={onDelete} accessibilityLabel={deleteAccessibilityLabel}>
            <ButtonIcon name="chevron-left" />
          </Button>
        </View>
      </View>
    </View>
  );
}
