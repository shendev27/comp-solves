import java.util.Scanner;

public class main{
    public static void main(String[] args) {
        try (Scanner input = new Scanner(System.in)) {
            int testCases = Integer.parseInt(input.nextLine());
            for (int testcase = 0; testcase < testCases; testcase++) {
                int turkeys = input.nextInt();
                int goats = input.nextInt();
                int horses = input.nextInt();
                System.out.println((turkeys*2)+(4*(goats+horses)));
            }
        }
    }
} 
