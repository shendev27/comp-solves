import java.util.Scanner;

public class main {
    public static void main(String[] args) {
        try (Scanner input = new Scanner(System.in)) {
            int testCases = Integer.parseInt(input.nextLine());
            for (int testcase = 0; testcase < testCases; testcase++) {
                String line = input.nextLine();
                String w1 = line.substring(0, line.indexOf("|"));
                String w2 = line.substring((line.indexOf("|") + 1));
                if (w1.equals(w2)||(w1.length() != w2.length())) {
                    System.out.println(line + " = NOT AN ANAGRAM");
                } else {
                    String[] word1 = new String[w1.length()];
                    String[] word2 = new String[w1.length()];
                    for (int i = 0; i < w1.length(); i++) {
                        word1[i] = String.valueOf(w1.charAt(i));
                    }
                    for (int i = 0; i < w2.length(); i++) {
                        word2[i] = String.valueOf(w2.charAt(i));
                    }
                    int count = 0;
                    for (int i = 0; i < word1.length; i++) {
                        int c1 = 0;
                        int c2 = 0;
                        String comp = word1[i];
                        for (int j = 0; j < word1.length; j++) {
                            if (word1[j].equals(comp)) {
                                c1++;
                            }
                        }
                        for (int k = 0; k < word2.length; k++) {
                            if (word2[k].equals(comp)) {
                                c2++;
                            }
                        }
                        if (c2 != c1) {
                            count++;
                        }
                    }
                    if (count > 0) {
                        System.out.println(line + " = NOT AN ANAGRAM");
                    } else {
                        System.out.println(line + " = ANAGRAM");
                    }

                }

            }
        }
    }
}
